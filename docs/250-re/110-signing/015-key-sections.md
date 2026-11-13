# 015. Секции подписей и ключей (ITOC) и вольты

> Источник: статический разбор OSS mstflint (`refs/src/mstflint`, rev `a2b9858b`):
> `flint_base.h:382-386`, `image_info_layouts.h`,
> `tools_layouts/image_layout_layouts.h` (2026-09-06); слот-формат вольтов и
> auth-биты — журналы `2026-10-29-securefw-gates-task-01` §1.3-1.5,
> `2026-10-30-cx6dx-securefw-task-01`, `2026-10-30-cx6dx-introspection-task-01`;
> поправка флагов — отчёт `2026-10-27-securefw-boot-gate-experiments.md` §1.
> Связи: механизм → `005-mechanism.md`; payload → `010-payload.md`; CLI →
> `020-cli.md`; SB-подписи → `025-secure-boot.md`; live-гейты secure-fw →
> `750-exp/170-securefw-live-gates.md`; secure_fw-бит карты (MGIR) →
> `065-secure-fw-bit.md`.

## 1. Типы секций

Типы секций (`flint_base.h:382-386`, `image_info_layouts.h`):

| Тип | Имя | Содержание |
|---|---|---|
| `0xA0` | `FS3_IMAGE_SIGNATURE_256` | digest/RSA-2048 под **весь образ** |
| `0xA1` | `FS3_PUBLIC_KEYS_2048` | публичные ключи RSA-2048 (слоты) |
| `0xA3` | `FS3_IMAGE_SIGNATURE_512` | digest/RSA-4096 под **весь образ** |
| `0xA4` | `FS3_PUBLIC_KEYS_4096` | публичные ключи RSA-4096 (слоты) |
| `0xA5` | `HMAC_DIGEST` | 3×64B HMAC (FS4, `sign_with_hmac`) |
| `0xA6` | `FS4_RSA_PUBLIC_KEY` | публичный ключ secure-boot (FS4) |
| `0xA7` | `FS4_RSA4096_SIGS` | secure-boot подписи (boot/crit/non-crit) |

## 2. Layout секций подписи

`tools_layouts/image_layout_layouts.h`:

- `image_layout_image_signature` (:828, 320B): `signature_uuid[16]@0x00`,
  `keypair_uuid[16]@0x10`, `signature[64]@0x20` (256B = RSA-2048);
- `image_layout_image_signature_2` (:845, 576B): `signature[128]@0x20`
  (512B = RSA-4096);
- `image_layout_secure_boot_signatures` (:1027, 4352B):
  `boot_signature[512]@0x00`, `critical_signature[512]@0x200`,
  `non_critical_signature[512]@0x400` (каждая TOCPUn'd,
  `storeSecureBootSignaturesInSection` `fs4_ops.cpp:5047`).

**`keypair_uuid`** — UUID пары ключей, которым подписали. У digest-only образов
`keypair_uuid = 0x00…` (ключ не участвовал); у RSA-подписи — реальный UUID,
который должен совпасть с UUID публичного ключа в `0xA1`/`0xA4`/`0xA6`, иначе
карта подпись отвергнет.

## 3. Вольты: слоты публичных ключей

Слот `0xA1`/`0xA4` (`image_layout_file_public_keys_2`,
`tools_layouts/image_layout_layouts.h:285-299`):

| Поле | Смещение | Размер |
|---|---|---|
| `auth_cfg` (auth-биты) | 0x0 | 4B |
| `exp` (65537) | 0xC | 4B |
| `keypair_uuid` | 0x10 | 16B |
| `key` (modulus) | 0x20 | 512B (RSA-4096) |

Слот = 544B (0x220); секция `0xA4` = 8 слотов = 4352B (0x1100). Слова BE,
сырые, как в секции (журнал `2026-10-29-securefw-gates-task-01` §1.3).

`0xA6` = 8×544B `public_keys_3` **с переставленными полями**: `exp@0x0`,
`uuid@0x4`, `modulus@0x14`, `auth_cfg@0x214` — контент ключей идентичен `0xA4`,
layout другой (CX-6Dx; журнал `2026-10-30-cx6dx-securefw-task-01`).

`auth_cfg` = `component_authentication_configuration`
(`image_layout_layouts.h:60-102`): auth_type (биты 0-7: 0=NULL,
1=SHA256Digest, 3=RSA-2048, 4=RSA-4096; `CheckPublicKeysFile`
`fs3_ops.cpp:3475/:3485`) + enable-биты dword0: bit22 `mlnx_cert_en`, bit23
`vendor_cert_en`, bit25 `c_r_token_en`, bit26 `btc_token_en`, bit27 `frc_en`,
bit28 `mlnx_nvconfig_en`, bit29 `vendor_nvconfig_en`, bit30 `cs_token_en`,
bit31 `fw_en` (журнал `2026-10-29-securefw-gates-task-01` §1.3). Минимум для
FW-ключа: auth_type=4 + fw_en = `0x80000004`; вендорский HPE slot0 =
`0xD8000004` (расширенный набор). Ключи типизированы по назначению — то же
семейство флагов документируют скрытые NV-TLV `file_public_key{,_4096,_4096_a,
_4096_b}` (SQLite-DB mlxconfig
`refs/src/mstflint/mlxconfig/mlxconfig_dbs/mlxconfig_host.db`, 2026-10-01).

Клиентский резолв «ключа образа»: первый слот `0xA4`/`0xA6` с `fw_en==1`
(`FindImagePublicKeyInPublicKeys2/3` `fs4_ops.cpp:4719-4733`/`4763-4777`);
`StoreImagePublicKeyInPublicKeys2` замещает найденный fw_en-слот новым ключом
(`fs4_ops.cpp:4779-4834`; журнал `2026-10-29-securefw-gates-task-01` §1.5).

Эмпирика вольтов по корпусу CX-6Dx (журнал
`2026-10-30-cx6dx-introspection-task-01`): 4096-пара Mellanox-корней
(`c55d54e8…`/`c1da650b…` + `f560c160…`/`b99b3eb4…`, обе auth=0xd8000004)
константна на всех secure-образах (retail = FB = Dell = OEM); `0xA1`-2048 —
по эре FW (22.50 → `2c635b71…`; 22.27/22.32 → `ec897142…`, обе auth_type=3
frc_en); non-secure — keyless. Полная таблица сигнатур/ключей по образам —
приложение `005-mechanism.md`.

## 4. Флаги security-режима в IMAGE_INFO

Flags security-режима образа — в **IMAGE_INFO** (DWORD[0],
`image_info_layouts.h:169-208`): `mcc_en`@bit8, `signed_fw`@bit14 («digest
зашифрован» — см. постулат в `025-secure-boot.md`), `secure_fw`@bit15
(«cr-space closed»). Флаги занимают **байт 2** DWORD[0] (byte1 =
minor_version) — поправка к ранней формулировке «биты DWORD[0]» (отчёт
`2026-10-27-securefw-boot-gate-experiments.md` §1).

Значения по классам образов (с учётом поправки byte-2): OEM-образы несут
`signed_fw=1/secure_fw=1`; generic `MT_` — только `mcc_en` (отчёт
`2026-10-27-securefw-boot-gate-experiments.md` §1); ini 0x30 CDA-SKU токенов
`mcc_en/signed_fw/secure_fw` не содержит → FW strict default (журнал
`2026-10-28-burn-digest-gate-task-06`, п.6 «ini-токены v5r»). Раннее
утверждение «у всех локальных образов signed_fw=0/secure_fw=0» (2026-09-06,
до поправки byte-2) — устарело, снято наблюдением OEM=1/1.

Флаги образа — **не индикатор** наличия RSA-подписи (наличие видно по секциям
`0xA0/0xA3`) и **не переключатель** поведения карты: эксперимент B2 (flags
`0x01→0xC1→0xd9` на generic-базе) на boot-гейт не повлиял; secure-состояние —
атрибут карты (MGIR), не образа (отчёт
`2026-10-27-securefw-boot-gate-experiments.md`; отчёт
`2026-10-28-securefw-legends.md`, п.3/11).
