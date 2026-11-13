# 020. Патч-матрица: секция → что можно менять → зависимые CRC/поля

> Источник (перенос из плоского дока 10 §7–7.1, диспозиция спеки §4.1):
> матрица и правила — эмпирика циклов dell-base-rework / eda-ib-node
> (live 2026-09-13, логи `refs/fw/cx-5-6/t53*-2026-09-13.log`);
> смешиваемость/flash-пути/дайджест — спека
> `docs/superpowers/specs/2026-09-10-eda-ib-node-design.md`
> §3.1–§3.5; доказательства — `docs/750-exp/110-dell-base-rework` (E1/E3/E5),
> `docs/850-howto/140-fw-upgrade`, `docs/850-howto/100-cross-flash-ops` §6,
> журналы ch2 T2.1/T2.2; digest-модель — цикл burn-digest 2026-10-28,
> `docs/superpowers/reports/2026-10-28-burn-digest-gate-results.md` §1-2.
> Это спецификация инструмента (mlxfwutil): все зависимости CRC/полей —
> полностью.
>
> Связи: CRC-алгоритм — `docs/250-re/100-formats/025-crc.md`; burn-order —
> `…/050-fs4-burn-order.md`; hashes table — `…/035-fs4-hashes.md`; ini/0x30 —
> `010-ini-mapping.md`; подпись — `docs/250-re/110-signing/`.

## 1. Матрица: секция → что можно менять → что пересчитывать

| Секция (type) | Что можно менять | Что пересчитывать |
|---|---|---|
| 0x12 FW_MAIN_CFG | бинарный конфиг (порты/скорости/PCIe; см. `cx5_gen4_enable.py` offsets) | section_crc записи; entry_crc; (signed → повторная подпись) |
| 0x08 HW_BOOT_CFG | link training: byte 0x23 = max PCIe speed (0x07→0x0F); byte 0x22 = PCIe-topology/плата (0x00=x8, 0x01=x16 std, 0x03=OCP — 8008-CDAN/1012-EDAN в refs — OCP, **8008-ECA = 0x01 (std)**: урок «все 8008-x16 в refs — OCP» пересмотрен, docs/750-exp/120-eda-ib-node §4.9) | то же |
| 0x09 HW_MAIN_CFG | port PCIe gen @ 0x245/0x285; speed tables @ 0x404+; Gen4 PHY-tuning @ 0x86c..f (per-card значения; {CDA,EDA,ECAT}=62fc62fc — docs/750-exp/110-dell-base-rework, docs/750-exp/120-eda-ib-node §5.3) | то же |
| 0x11 FW_BOOT_CFG | PCIe capability advertisement @ 0x93 (0x45→0x47, cap_index Gen3→Gen4); Gen4 x16 marker @ 0x47 (0x18→0x1a — docs/750-exp/110-dell-base-rework); per-port vpi link-type @ 0x2b7/0x2bb (биты {b0=net_ib,b1=net_eth,b2=def_ib,b3=def_eth}: **0x0a=EN** (eth-only, def-eth) — все EN-карты; **0x07=VPI** (ib+eth, def-ib) — все VPI-карты; 0x00=неисп. порт; **0x0b=VPI def-ETH** (ib+eth, def-eth) — в лестнице не
  встречается; **0x03 (ib+eth, без def)** — ни у одной лестничной карты,
  ch5-перекодировка «def-ETH» (t53/t53g): сам по себе НЕдостаточен для
  100G-линка, docs/750-exp/120-eda-ib-node §5.5; **live 2026-09-13: 0x0a (EN) и 0x0b (VPI
  def-ETH) работают БЕЗ NV-override** (t53h/t53i) — выбор: EN-лок vs
  «VPI + дефолт ETH») | то же |
| 0x30 DBG_FW_INI | замена ini (новый zlib-стрим; размер ≤ size или менять запись) | size/flash_addr записи → entry_crc; section_crc; header `num_of_entries` (FS4) — нет (размер списка не меняется) |
| 0x10 IMAGE_INFO | PSID, name, description, строки версии | section_crc/entry_crc; копия в MFG_INFO (FS3) при смене PSID |
| 0xE0 MFG_INFO | копия PSID (FS3) | то же |
| 0xE1/0xE7/0xE8 DEV_INFO / FS4_DEV_INFO1/2 | служебные данные устройства | section_crc/entry_crc |
| 0xE2/0xE4/0xE6 NV_DATA0/1/2, 0xE5 FW_NV_LOG | NV-данные | section_crc (у dev-секций часто no_crc=1 — проверять по записи) |
| 0x01-0x07, 0x18 код (BOOT/PCI/MAIN/ROM) | не рекомендуется (MAIN_CODE ещё и per-line CRC 64+4) | section_crc + line-CRC'ы (FS4) + подпись |
| 0xA0-0xAD подпись | **не трогать вручную** — пересчитывается при подписании | весь блок подписи (RSA, docs/250-re/110-signing/015-key-sections.md) |

Правила:

- Любое изменение данных секции → пересчитать `section_crc`
  (байты 0x1A-0x1B записи) алгоритмом `docs/250-re/100-formats/025-crc.md`.
- Изменение size/flash_addr/параметров записи → пересчитать entry-CRC
  (0x1E-0x1F) по первым 28 байтам записи.
- Для signed-образов любое изменение данных инвалидирует подпись
  (RSA-сигнатуры 0xA0/0xA3/0xA7) — нужен свой ключ или FNP-режим
  (см. `cx5_gen4_enable.py:619-620` README-заметку и docs/250-re/110-signing/010-payload.md).
- У секций с `no_crc`/crcf=1 (подписи, dev-данные) section_crc = 0x0000 —
  не пересчитывать.

## 2. Per-port VPI link-type: байт образа vs mstconfig NV-override

**mstconfig LINK_TYPE (per-port VPI; live CX-5, ch1 T1.3 + ch5):**

- Кодировка: IB=1, ETH=2, VPI=3; `Default=0` — «auto из образа»; `*` в
  левой колонке = modified. **Settable на CX-5 — только {IB(1), ETH(2)}**:
  `VPI(3)`, `3` и `0` отклоняются (`-E- Unknown value VPI/3/0`, live
  2026-09-13, лог `refs/fw/cx-5-6/t53i-2026-09-13.log`; VPI(3) как
  set-значение — паттерн CX-2/3 по знанию владельца, на CX-5 «VPI-режим» —
  свойство байта образа, а не NV-значения). Возврат к «auto из образа» —
  burn с `--ignore_dev_data` (проверено task-04b) или `mstconfig reset`
  (проверено live 2026-09-13: стирает NV, применяется после reboot;
  `-e q` после reset+reboot: P1 `0 0 0` без `*` — «0» без имени enum во
  всех колонках; P2 `IB(1) IB(1) IB(1)` — image-derivative по байту 0x07,
  не NV). Три колонки Default/Current/Next Boot — `mstconfig -e -d <bdf> q`
  (`-e` ПЕРЕД подкомандой; без `-e` — одна колонка «Next Boot»). set — и
  именем (`LINK_TYPE_P1=ETH`), и числом (`=2`); при pending-значении `-e q`
  добавляет 4-ю колонку «New» (`* 0 0 ETH(2)`); `mstconfig … r` — алиас
  reset (live 2026-09-13, тот же лог). Доступ (docs/750-exp/120-eda-ib-node
  §5.5): toolbx с PCI (владелец, 3 колонки) или контейнер t-adm; сервер без
  `mlxconfig_host.db` и шелл координатора без PCI — mstconfig не работает.
- NV-override хранится в DTOC `0xE6 NV_DATA0` (MTCF-контейнер; TLV
  `nv_vpi_link_type` id 0x12 — ch1 T1.3): «default в образе» (байт
  `0x11+0x2b7/0x2bb`) ≠ «applied override» (NV). `mstflint burn` с
  `--ignore_dev_data` (+ `--nofs`) стёр NV-override (доказано:
  POST-BURN `LINK_TYPE_P1 0/0/0` без `*` — image-default,
  docs/750-exp/120-eda-ib-node §5.5).
- Эксперимент (task-04b, docs/750-exp/120-eda-ib-node §5.5): байт
  `0x11+0x2b7=03` (def-ETH) сам по себе НЕдостаточен — port0 становится
  ETH-функцией (link layer), но speed-конфиг остаётся 1000baseKX-only
  (21 мин без link); NV-override `LINK_TYPE_P1=ETH(2)` обязателен
  (паттерн docs/750-exp/160-hpe-cx5-vpi-gen4-precheck: у HPE VPI-карты он
  в NV) — после `mstconfig set` + reboot 100G up за ~13 c.
  **Оговорка** (live 2026-09-13, владелец, лог
  `refs/fw/cx-5-6/mstconfig-reset-2026-09-13.log`): после `mstconfig
  reset` + reboot (то же P1=0, тот же флэш) port0 advertise'ит **полный
  100G-набор** (не 1000baseKX-only), но линк всё равно не поднимается ни
  с DAC («Unsupported cable»), ни с оптикой.
- **Резолюция (t53h, live 2026-09-13, лог
  `refs/fw/cx-5-6/t53h-2026-09-13.log`):** корень — перекодировка байта
  `0x03` (не «def-ETH», а «ib+eth, без default»; см. строку 0x11 в §1).
  `0x11+0x2b7=0a` (EN — значение всех EN-карт) + burn
  `--ignore_dev_data` → port0 100G (DAC) **без NV-override**; в
  `mstconfig -e q` строка `LINK_TYPE_P1` отсутствует вообще (порт
  EN-locked), P2 `IB(1)×3`. Финальный рецепт: 0x0a в образе; NV-override
  `ETH(2)` — вендорный VPI-паттерн (docs/750-exp/160-hpe-cx5-vpi-gen4-precheck)
  для 0x07-байта.
- **Вариант «оставить выбор» (t53i, live 2026-09-13, лог
  `refs/fw/cx-5-6/t53i-2026-09-13.log`):** `0x11+0x2b7=0b` (VPI def-ETH:
  ib+eth, default eth) — порт снова VPI-выбираемый: `LINK_TYPE_P1 =
  ETH(2) ETH(2) ETH(2)` без `*` — **колонка Default теперь показывает
  `ETH(2)`** (image-default из бита def_eth; у 0x07/0x03 — `0`), port0
  100G (DAC) **по умолчанию, без NV**; переключить в IB — `set
  LINK_TYPE_P1=IB` (NV). t53i — текущее состояние карты (2026-09-13).

## 3. Смешиваемость частей (FS4; фаза EDA→IB, верифицировано 2026-09)

| Часть (ITOC) | Миксуется? | Доказательство |
|---|---|---|
| Код ASIC (0x02–0x07) | **Пересадка в чужую базу — нет** (digest). **Как новый base целиком — да** | E1/T2.2 (reject); E2/E3 (чистый 8008-base бутится на Ex-карте); gen4 Option B; 8008-код на ECA-кремнии — docs/750-exp/120-eda-ib-node §5.2 |
| PHY-код/константы (0x0a/0x0b/0x0c) | В наших 1012-образах идентичны — не переменная | diff CDA↔ADA 2026-09-12; E4 |
| HW-конфиг (0x08 HW_BOOT_CFG, 0x09 HW_MAIN_CFG) | **Да — проверено частично (T4.2/T4.3)**: подмена 0x08/0x09 структурно чиста (xhw прошёл офлайн-гейт); образ 8008-ADA = no-boot на этом железе в обоих вариантах 0x08/0x09 (SFP28 из 8008-ADA, QSFP28 из 4030-ri) — блокёр no-boot НЕ в 0x08/0x09; роль в типе/рейте портов — **не верифицирована** (база не бутится). **Board-профиль шире 0x08/0x09**: board-поля ещё в 0x11 (sub/PCIe-gen/SR-IOV/link-type), 0x12 (speed mask/width/VPI), boot-записи [0x100–0x10f] (6B) и идентичности (0x10/0xe0/0xa0); код board-независим (8008-ADA↔8008-CDAN: 0x02–0x07/0x0a–0x0c/0x18 идентичны побайтово) | diff CDA↔ADA (2B + 82B); T4.0–T4.3; board-дельта 8008-ADA↔8008-CDAN + byte-таблицы 7 плат (docs/750-exp/120-eda-ib-node §4.8, журнал 2026-09-12-ch4-no-boot-root-cause) |
| FW-конфиг (0x10 IMAGE_INFO/PSID/device/sub, 0x11 FW_BOOT_CFG, 0x12 FW_MAIN_CFG) | Да | E5, gen4, T2.2 (device-prompt) |
| ROM (0x18) | Да (device-ID mismatch — prompt `-y`) | E3-V3/V4, E4, T2.2, **T4.1** (проверено: ROM 8008 на 1012-CDA-базе принят, device-ID warning только; docs/750-exp/120-eda-ib-node гл. 4) |
| .ini (0x30) | Да — **и не функционален при boot** (информативный текст; рантайм читает бинарные 0x11/0x12): E5 бутится на SFP28-x8-железе с чужим EDA-ini (QSFP28 x16 Gen4, VPI; `E5-0x30 == 1012-EDA-0x30`). **Формат: zlib-сжатый текст** (`78da`; разворачивается iniprep-текстом ~14–17 KB, в шапке — имя prs-источника и FW-версия; верифицировано 2026-10-28: Dell 6120 3060B→16.5KB `from ./cx5_dell_2p_100g.prs`, CDA 4030 2344B→13.8KB `from ./cx5_MCX516A_2p_x16_pci4.prs`; классификатор — section_meta_probe.py `ZLIB_TYPES={0x30,0x32,0x33}`) | E5 (docs/750-exp/110-dell-base-rework); docs/750-exp/120-eda-ib-node §4.8; zlib-чек 2026-10-28 |
| Подпись (0xA0–0xA5) | **Нет** (от базы; non-SB — не переподписываем) | E1; docs/850-howto/100-cross-flash-ops §12 |
| Сервисное (0x32/0xe9/0xeb) | Не исследовано | TODO.md |
| DTOC (MFG_INFO, DEV_INFO, NV_DATA, VPD_R0, FW_NV_LOG) | Сохраняется plain/legacy-burn'ом; **FNP перезаписывает** (→ `sg`/`guides`) | E0/T2.1 vs T15; `docs/250-re/100-formats/035-fs4-hashes.md` |

**8008-код на ECA-плате (MCX556A-ECAT, MT27800/0x1017) — проверено live
(2026-09-12, docs/750-exp/120-eda-ib-node гл. 5):** T5.0 — 8008-ECA
verbatim boot, H4 исключена (§5.2); T5.2 — Gen4 (4 поля 0x08/0x09/0x11,
16GT/s x16, §5.4); T5.3 — порт-конфиг (port0 ETH / port1 IB; §5.5: байт
`0x11+0x2b7=03` — мисдекод def-ETH-метки; ad-hoc t53h/t53i (2026-09-13):
`0x0a` (EN) и `0x0b` (VPI def-ETH) в образе работают **без NV-override**;
текущее состояние карты = t53i). Итог — IB-узел: port1 IB Active
QDR (LID 13, Rate 40, ib_write_bw 31.2 Gb/s) + port0 100G ETH + Gen4 x16
(§5.6; финальный raw `970636c6…`, valid B).

## 4. Flash-пути и digest-модель

| Путь | Digest-проверка | Modified-образы | Когда |
|---|---|---|---|
| **plain** (MCC, running FW) | да | **нет** (только байт-в-байт вендорные) | штатные вендорные апгрейды |
| **legacy** (`-apc`/`--nofs`; `_mccSupported=false`) | нет | **да** (non-SB) | **наш основной путь** (E3/E5/T2.1; docs/850-howto/140-fw-upgrade `--no_fw_ctrl`) |
| **FNP** (strap; нет running FW) | нет | да | SB-карты / recovery (T15) |

Digest-модель (верифицировано; обновлено 2026-10-28 — цикл burn-digest,
`docs/superpowers/reports/2026-10-28-burn-digest-gate-results.md` §1-2):

- Гейт plain burn (MCC, running FW) = **безусловный content-digest всего
  образа** (type-7 компонент на стадии VERIFY; секционной дискриминации
  нет). Ранняя версия «код да / конфиг нет» — ОПРОВЕРГНУТО 2026-10-28:
  артефакт смешения путей (E5/E3 шли legacy → гейт не выполнялся;
  реаттрибуция — draft §4).
- **Причина отвержения кастомных образов — стылый 0xA0-дест**: mlxfwutil его
  не пересчитывает; кастомная линейка наследует сток-дест базы. Дест
  лежит внутри секции 0xA0 на смещении **+0x20** (перед ним uuid-поля:
  `signature_uuid[16]@+0x00`, `keypair_uuid[16]@+0x10` —
  tools_layouts/image_layout_layouts.h:828). Фикс: `mstflint -i <img>
  sign` (без ключей = FwInsertSHA256) — plain MCC-burn принимает
  контент-модифицированный образ (live-доказано парным контролем; draft
  §1). Нюанс пробников: verify_sha.py, читавший [0:32] секции, видел
  uuid-нули — фактический дест на +0x20.
- Отклонённый burn **записывает** целевой (неактивный) слот ДО VERIFY:
  стирание — фаза INITIALIZE, тело — DOWNLOAD (T2.2: 4 406 051 B ≈
  4.20 MiB residue; ACTIVATE при отказе не исполняется — слот не
  финализирован, карта ботит со старого; draft §2 / журнал task-01 §2.1).
- legacy flow (`-apc`/`--nofs`) принудительно `_mccSupported=false`
  (docs/850-howto/100-cross-flash-ops §6, строка 138;
  flint/subcommands.cpp:2590-2594) — modified-образы прошиваются
  (E3, E5, T2.1): FW digest-гейт при этом **вообще не выполняется**
  (прямой flash-путь).
- FNP — нет running FW → нет проверки (T15).
- ROM device-ID mismatch = prompt/warning, **не блок**: дословный текст
  (T2.2): `Image file ROM: FW is for device 4121, but Exp-ROM is for device
  4119` → `-y`; mixed-ROM бутятся (E3-V3/V4).

## 5. Офлайн-гейт и post-burn sanity (обязательные)

**Офлайн-гейт (обязателен для КАЖДОГО собранного образа до переноса на
сервер; урок E1):**

1. `python3 mlxfwutil.py verify <img>` — CRC всех секций + честная семантика
   (mDevInfo single-valid, hashes table если присутствует) **+ инвариант
   burn-order** (`docs/250-re/100-formats/050-fs4-burn-order.md`;
   `--sector-size` при иной гранулярности флеша — default 64K).
2. `mstflint -i <img> verify` — независимая проверка.
3. `mstflint -i <img> q` — идентичность как ожидается (версия, PSID,
   device, Rom Info, description).
4. Структура: все ITOC-секции < 0x800000 (8MiB-half), образ декодируется
   (`ab`/ITOC), reflow при несовпадении размеров — автоматика.

md5 образа + вывод гейта → журнал. Только прошедший гейт несётся на карту.

**Post-burn sanity (обязателен после КАЖДОГО burn + reboot; урок Bad CRC):**

1. `mstflint q` — Base GUID/MAC ≠ N/A (значения карты).
2. `mstflint dc` — работает (не Bad CRC).
3. `mstconfig q` — работает.

При N/A/Bad CRC: `python3 mlxfwutil.py guides` (self-verify,
docs/750-exp/140-post-fnp-guid-desync §8.8) → не помогло — FNP + `sg`
(значения из baseline). Результат → журнал.
