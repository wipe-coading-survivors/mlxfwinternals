# 025. Secure Boot: подпись VERSION_1 / VERSION_2

> Источник: статический разбор OSS mstflint (`refs/src/mstflint`, rev `a2b9858b`),
> `fs4_ops.cpp` (2026-09-06); формулы V1 и HW-поинтеры — журналы
> `2026-09-20-fw-iron-boot-chain`, `2026-10-30-cx6dx-securefw-task-01/-05`;
> эмпирика AE↔AC — пробник `scripts/probes/sign_diff.py`, образы `refs/fw/`
> (2026-09-06).
> Связи: механизм → `005-mechanism.md`; payload → `010-payload.md`;
> секции/вольты → `015-key-sections.md`; root-of-trust → `030-root-of-trust.md`;
> CX-6Dx-детали → `055-cx6dx-signing.md`; live boot/burn-гейты →
> `750-exp/170-securefw-live-gates.md`.

## 1. Выбор версии

`getSecureBootSignVersion` (`fs4_ops.cpp:5170`): `VERSION_2` если валиден
HW-поинтер `hashes_table` (Carmel+; таблица —
`docs/250-re/100-formats/035-fs4-hashes.md`), иначе `VERSION_1`.

Факт (CX-6Dx 22.50.1002): активна **VERSION_1** — hashes_table raw
`0xFFFFFFFF` (→ 0x0 после fixup) = invalid ⇒ V2-маски
(`RemoveCRCsFromMainSection`, `MaskBootRecordCRC`) не действуют ни для
`0xA3`-, ни для `0xA7`-подписи; применение V2-маски ломает паритет
(негатив-контроль). Ограничение клиента: `getBootRecordSize` не имеет кейса
CX6DX — при валидном hashes_table V2-путь mstflint на CX-6 упал бы (журнал
`2026-10-30-cx6dx-securefw-task-01`).

## 2. `SignForSecureBoot` (последовательность)

`SignForSecureBoot` (`fs4_ops.cpp:5182`):

1. (v2) `SetImageIVHwPointer`;
2. `StoreImagePublicKey(pub_key, uuid)` — ключ → `0xA6`/`0xA4`
   (`StoreImagePublicKeyInPublicKeys3` `fs4_ops.cpp:4836`,
   `component_authentication_configuration{fw_en, auth_type}` + слоты
   `public_keys_2/3`);
3. `getBootDataForSign` (`fs4_ops.cpp:4503`) — данные boot-области
   (image signature, hw pointers, boot record, TOC, boot2);
4. `signer.Sign(boot_data, boot_signature)`;
5. (v1) дополнительно подписи `critical` и `non_critical` (все остальные
   ITOC);
6. `storeSecureBootSignaturesInSection` → `0xA7`.

## 3. Формулы VERSION_1 (parity бит-в-бит, CX-6Dx 22.50)

- **boot** = `[auth_start..auth_end]` = **[0x0..0x6fff]** raw, без масок —
  окно = magic + version + HW-поинтеры + boot_record + tools + boot2 + ITOC
  («iron image»; HW-поинтеры authentication_start/end — журнал
  `2026-09-20-fw-iron-boot-chain`).
- **critical** = {PCIE_LINK_CODE `0x04`, HW_BOOT_CFG `0x08`,
  PCIE_PHY_UC_CODE `0x0c`} в порядке таблицы ITOC, секция + 0xFF до 0x80
  (RE-факт CX-6Dx; клиентский список имён секций в mstflint — HW_BOOT_INI,
  PCIE_PHY_UC_COMMANDS, PCIE_LINK_CODE — статический разбор 2026-09-06).
- **non-critical** = все прочие ITOC-секции кроме `0xA0/0xA3/0xA7` и critical.

Обе подписи (`0xA3` и `0xA7`) воспроизведены **бит-в-бит** на вендорском
образе + self-verify на self-signed сборках (гейт
`scripts/cx6secfw/parity_gate.py`; журнал
`2026-10-30-cx6dx-securefw-task-05`). Вольты `0xA4/0xA6/0xA7` входят в
подписываемые данные `0xA3` ⇒ порядок сборки «вольт → подпись» (`010-payload.md`);
uuid в `0xA3.keypair_uuid` — только из CLI `--key_uuid`.

## 4. Целостность TOC и инвалидация

Проверка целостности TOC: `CheckTocSignature` (`fs4_ops.cpp:191`) через
`{first_signature, TOC_RAND1/2/3}`. После прошивки старая подпись
инвалидируется: `DoAfterBurnJobs` (`fs4_ops.cpp:2405`).

## Приложение: диф AE (no-SB) ↔ AC (SB), CX-6Dx rel-22_50_1002

Файлы: `refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435A{E,C}-…`
(оба 32MB, 29 записей ITOC, ITOC @ 0x5000). **Оба образа имеют одинаковые
29 записей ITOC** (включая `0xA0/0xA3/0xA6/0xA7`) — «signed/unsigned»
различается **данными**, а не наличием секций. 200 диф-диапазонов, 7916 байт:

- **IMAGE_INFO** (`@0x6af400`): PSID `MT_0000000696` (AE) vs `MT_0000000695`
  (AC); device_id байт `0x71` (AE) vs `0x70` (AC) (и в `FW_BOOT_CFG+0x002D`);
  desc `…Crypto; No Secure Boot` vs `…Crypto and Secure Boot`;
  name/prs `…E…_no-SB.prs` vs `…C…_SB.prs` ⇒ **AE и AC — разные SKU**
  (board-варианты E/C), а не «один образ с/без подписи». Но именно эта пара
  показывает, что добавляет Secure Boot.
- **Секции подписи/ключей**: AE — `0xA0` digest(31B), `0xA3`/`0xA7` пустые,
  `0xA6` маркер; AC — `0xA3` RSA-4096(524B), `0xA7` secure-boot(1519B),
  `0xA6` реальный ключ(1056B), `0xA0` пуст.
- **CRC секций** в ITOC (`sec_crc`): различаются у `IMAGE_INFO`,
  `FW_BOOT_CFG`, `PUB_KEYS_2048`, `PUB_KEYS_4096`, `FS4_RSA_PUB_KEY`;
  у `0xA0/0xA3` `crcf=1` (CRC секции не считается).
- Суффикс part-number **не переносится на вендорские схемы**: корреляция
  `AE→no-SB`/`AC→SB` верна только для собственной схемы Mellanox
  (`MCX623435A[E,C]`); Facebook — `MCX623435MC-CDAE_FB`, и это secure-fw
  (PSID `FB_0000000018`, `0xA3/0xA6/0xA7` = общий ключ Mellanox, ITOC @
  0x5000). **Надёжный индикатор SB — IMAGE_INFO `secure_fw`-бит /
  `mstflint q` «Security Attributes», а НЕ буква в part-number.**

## Постулаты / открытое

- [постулат] **`signed_fw`-бит** IMAGE_INFO (bit14, «digest зашифрован»): как
  именно шифруется digest при bit14=1 — неизвестно (стоковые/digest-only
  образы — бит=0; OEM несут bit=1 — `015-key-sections.md` §4). Поздние циклы
  (burn-digest / securefw-gates / cx6dx, 2026-10) механику не вскрывали.
  Рядом — неисследованный клиентский путь `FwInsertEncSHA`
  (`fs3_ops.cpp:3323+`): RSA-шифрованный SHA в сигнатурный слот без
  PKCS#1-обёртки `SignForFwUpdate` (журнал
  `2026-10-29-securefw-gates-task-01` §5) — связь с битом не доказана.
