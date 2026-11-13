# 005. Механизм подписи: mlxsign_lib и сигнатурные менеджеры

> Источник: статический разбор OSS mstflint (`refs/src/mstflint`, rev `a2b9858b`):
> `mlxsign_lib/`, `mlxfwops/lib/signature_manager*` (2026-09-06);
> parity-подтверждения формул — журналы `2026-10-29-securefw-gates-task-01/-03`,
> `2026-10-30-cx6dx-securefw-task-05`; эмпирика — образы `refs/fw/`
> (пробник `scripts/probes/sig_probe.py`).
> Связи: payload подписи → `010-payload.md`; секции ключей → `015-key-sections.md`;
> CLI → `020-cli.md`; Secure Boot → `025-secure-boot.md`; root-of-trust →
> `030-root-of-trust.md`.

«Подпись» в образах Mellanox — **два разных механизма** в одних и тех же секциях
ITOC (эмпирика — приложение):

- **SHA-256/512 digest** (32/64 байта в секции `0xA0`/`0xA3`, `keypair_uuid = 0`)
  — plain digest без ключа. Есть у **всех** стоковых образов Mellanox и у no-SB
  вариантов; по сути контрольная сумма (MCC/MCDA-поток).
- **RSA-2048/4096 подпись** (256/512 байта + `keypair_uuid ≠ 0`) — настоящая
  криптоподпись. Есть только у **OEM-signed / Secure-Boot** образов (Dell, HP,
  Facebook, CX-6Dx-SB).

## 1. mlxsign_lib (RSA + SHA, OpenSSL)

Библиотека `mlxsign_lib` (`refs/src/mstflint/mlxsign_lib/`) — единый интерфейс
подписания/хеширования. Типы (`mlxsign_com_def.h`):

| Тип | Назначение |
|---|---|
| `MlxSign::Signer` (базовый) | `Sign(data, out)` — подпись |
| `MlxSignRSA` / `MlxSignRSAViaOpenssl` | RSA-2048/4096; SHA-тип определяется размером ключа; публичный ключ читается из PEM (`PEM_read_RSA_PUBKEY` / `PEM_read_bio_RSA_PUBKEY`) |
| `MlxSignSHA256` / `MlxSignSHA512` | plain digest (`(*sha) << data; sha->getDigest(out)`) |
| `MlxSignHMAC` | HMAC-SHA256 (64-байтный ключ) |

`SHAType` enum: `SHA256`, `SHA512` (`mlxsign_com_def.h`). OpenSSL — опционален
(защита `#if !defined(NO_OPEN_SSL)`); без него RSA-подпись недоступна, digest —
да.

SHA-тип RSA-подписи — по длине приватного ключа: 0x100 (RSA-2048) → SHA-256,
0x200 (RSA-4096) → SHA-512 (`mlxsign_signer_interface.cpp:44-70`, дефолт
SHA512 :40; журнал `2026-10-29-securefw-gates-task-01` §1.3). EM fw-update-подписи
(0xA3) — RSA PKCS#1 v1.5 DER DigestInfo(SHA-512) — воспроизведён численно на
вендорских подписях (гейты `scripts/secfw/parity_gate.py` CX-5 и
`scripts/cx6secfw/parity_gate.py` CX-6Dx; журналы
`2026-10-29-securefw-gates-task-03` §3.4, `2026-10-30-cx6dx-securefw-task-05`).
FW-side верификация на burn-стадии ≡ клиентской формуле `SignForFwUpdate`
(маски/диапазон — `010-payload.md`).

## 2. Per-chip сигнатурные менеджеры

Слой — `ISignatureManager` (`mlxfwops/lib/signature_manager.h`) + фабрика-синглтон
`SignatureManagerFactory` (`mlxfwops/lib/signature_manager_factory.h`):

- `connectx6_signature_manager.cpp` — `AddSignature` пишет
  `3 * HMAC_SIGNATURE_LENGTH` (BOOT / CRITICAL / NON-CRITICAL);
- `connectx6dx_signature_manager.cpp` — пустой (только заголовок);
- `bluefiled_signature_manager.cpp` — отдельный.

`HMAC_SIGNATURE_LENGTH = 64` (`mlxfwops/lib/fs4_ops.h:47`).

## Приложение: сигнатуры по всем образам `refs/fw/` (2026-09-06)

Пробник: `scripts/probes/sig_probe.py` (ITOC → секции
`0xA0/0xA1/0xA3/0xA4/0xA6/0xA7`, «заполнено» = байты вне {0x00, 0xFF}).
`mcc/sfd/sfc` = биты IMAGE_INFO `mcc_en/signed_fw/secure_fw`.

| Образ | ФС | PSID | name / prs | `0xA0` SIG_256 | `0xA3` SIG_512 | `0xA6` FS4_PUBK | `0xA7` SB_SIGS |
|---|---|---|---|---|---|---|---|
| CX-4 MCX456A-ECA | FS3 | MT_2190110032 | `…2p_x16_edr.prs` | 32B digest | пусто | — | — |
| CX-4Lx MCX4121A-ACA | FS3 | MT_2420110034 | `…2p_x8_25g.prs` | 32B digest | пусто | — | — |
| CX-5 Ex MCX512A (stock) | FS4 | MT_0000000361 | `…2p_x8_25g_hb.prs` | 31B digest | пусто | 16B marker | — |
| CX-5 **Dell** 09FTMY (signed) | FS4 | DEL0000000004 | `cx5_dell_2p_100g.prs` | **270B RSA-2048** | **522B RSA-4096** | — | — |
| CX-5 **HP** 872726 (signed) | FS4 | HPE0000000009 | `cx5_hp_2p_x16_EDR_100g.prs` | **270B RSA-2048** | **525B RSA-4096** | — | — |
| CX-6 MCX654105A (stock) | FS4 | MT_0000000226 | `…vpi_200g_1p_hdr.prs` | 32B digest | пусто | 16B marker | — |
| CX-6Dx **AE** (no-SB) | FS4 | MT_0000000696 | `…Crypto_no-SB.prs` | 31B digest | пусто | 16B marker | пусто(0xFF) |
| CX-6Dx **AC** (SB) | FS4 | MT_0000000695 | `…Crypto_SB.prs` | пусто(0xFF) | **524B RSA-4096** | **1056B key** | **1519B sigs** |
| CX-6Dx **FB** `CDAE_FB` (ri) | FS4 | **FB_0000000018** | `…facebook_100g_1p_crypto.prs` | пусто(0xFF) | **RSA-4096** (common) | **RSA-4096 key** (common) | **SB sigs** |

`PUBK_2048(0xA1)` / `PUBK_4096(0xA4)`: stock/no-SB — 16–17B «маркер»
(`…01 00 01` = RSA e=65537, без реального ключа); signed — 274B / 1056B
реальные публичные ключи.

Паттерн:

- **stock Mellanox** (`MT_*`) и **no-SB** — только plain **SHA-256 digest**
  (32B, `keypair_uuid=0`);
- **OEM-signed** (Dell/HP/**Facebook**) — **RSA-2048 + RSA-4096** + реальные
  публичные ключи;
- **CX-6Dx SB** — только **RSA-4096** (`0xA3`) + secure-boot подписи (`0xA7`);
  `0xA0` у SB-варианта намеренно пуст (`0xFF`).

### keypair_uuid — маркер «digest vs RSA»

| Образ | `0xA0`.keypair_uuid | `0xA3`.keypair_uuid | `0xA4`.PUBK_4096.sig[0:8] |
|---|---|---|---|
| CX-6 stock | `0000…` (digest) | `ffff…` (пусто) | `0000…` (нет ключа) |
| CX-5 Dell | `a04a92ed0ade4084b7fab3c58f45a03b` | `c55d54e89ea74469b5e8d93572c2ff3d` | `c1da650b…` |
| CX-6Dx SB | `ffff…` (пусто) | `c55d54e89ea74469b5e8d93572c2ff3d` | `c1da650b…` |
| CX-6Dx **FB** | `ffff…` (пусто) | `c55d54e89ea74469b5e8d93572c2ff3d` | `c1da650b…` |

Dell CX-5, HP CX-5, Facebook CX-6Dx (`CDAE_FB`) и Mellanox CX-6Dx SB используют
**один и тот же RSA-4096 keypair** (`c55d54e8…`) и **тот же публичный ключ**
(`c1da650b…`) — общий корневой signing-ключ Mellanox. RSA-2048-ключи различаются
(`a04a92ed…` у Dell, `2c635b71…` у CX-6Dx). Уточнение по корпусу CX-6Dx
(журнал `2026-10-30-cx6dx-introspection-task-01`): 4096-пара Mellanox-корней
(`c55d54e8…` + `f560c160…`, оба auth=0xd8000004) константна на всех
secure-образах (retail = FB = Dell = OEM), вендор-специфичного end-ключа в
образах нет; 0xA1-2048 зависит от эры FW (22.50 → `2c635b71…`; 22.27/22.32 →
`ec897142…`); non-secure образы — keyless (uuid/modulus нули, `0xA3`=FF,
`0xA7`=0 блоков, fresh `0xA0`). Layout вольтов и auth-биты — `015-key-sections.md`.

## Дополнение (из 00 §3.2)

- Базовый `FwOperationsSignatureManager` — **no-op** (`AddSignature` →
  true): для классов без собственного менеджера (CX-4/CX-5) RSA-подпись в
  OSS-потоке **не добавляется** — OEM-образы (Dell/HP) подписаны вне OSS
  (приложение выше); явные команды подписания — `020-cli.md` §1.
