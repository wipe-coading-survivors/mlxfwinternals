# 060. NV-config vs secure_fw: поверхность lifecycle-ключей

> Источник: выемка из SQLite-DB mlxconfig
> (`refs/src/mstflint/mlxconfig/mlxconfig_dbs/mlxconfig_host.db`, таблицы
> `tlvs`/`params`; 1552 параметра, 815 публичных, 737 скрытых; кросс-чек
> исходников `rg reg_access_secure_host`) + live-серия 2026-10-01 (журналы
> `docs/superpowers/journal/2026-10-01-bazzite-cx6dx-lckeys-{probe,force-set,
> force437,reboot,fullkey}.md`, `2026-10-01-cx5-hpe-lckeys.md`).
> Связи: secure_fw-бит карты (MGIR, RO-состояние) → `065-secure-fw-bit.md`;
> root-of-trust (куда NV-дверь не ведёт) →
> `030-root-of-trust.md`; слот-формат вольтов/enable-биты →
> `015-key-sections.md` §3; boot-гейт generic-базы →
> `750-exp/170-securefw-live-gates.md`.

## 1. Переключателя secure_fw в NV-пространстве НЕТ

0 совпадений по `tlvs`/`params` (единственный ложный хит — `max_packet
lifetime`). Подтверждение: secure_fw/secure_boot/lifecycle — состояние
устройства (CR-space/OTP), не NV-TLV (реестр легенд №11: бит
`mgir.fw_info.secured` — RO-состояние живой карты).

## 2. `nv_secure_host` (TLV 0x19b) — NV-подложка MLOCK, не secure boot

TLV 0x19b «SECURE HOST», target NIC, 32 Б; параметры скрыты: `state` ENUM
`0x0 UNLOCKED / 0x1 LOCKED / 0x2 LOCK_FW_UPDATE / 0x3 LOCK_HOST_CFG` + `key`.
В OSS — `reg_access_secure_host(tools_open_mlock)` (`reg_access/reg_access.h:192`,
вызовы `fs3_ops.cpp:2938-2966`, `fsctrl_ops.cpp:1510-1537` — lock/unlock
устройства при burn). Это **secure host** (замок cr-space/flash-доступа с
ключом), НЕ secure boot; в CLI не экспонирован.

## 3. NV-слоты lifecycle-ключей (TLV 0x19c–0x19e): пассивное хранилище

`nv_ls_nv_public_key_0/1/2` (0x19c/0x19d/0x19e, size 32/256/256) — «LS NV
public keys» (ключи lifecycle-переходов): публичные токены
`LC_NV_PUB_KEY_{EXP,UUID,0_255,256_511}` — единственная найденная
«lifecycle-keying»-поверхность, доступная из mstconfig. Dedicated-логики в
OSS нет (DB-driven generic writer).

Live-серия на CX-6Dx GA SECURED (bazzite 03:00.0), затем повтор на CX-5
(`CARD_HPE_CX516A`, HPE 41:00.0) — факты (журналы 2026-10-01):

- Карта **не экспонирует** эти TLV («The Device doesn't support …
  parameter»): NVQC не поднимает канала; обычный `set` отвергается той же
  проверкой (suppRead=0). Скрытый `--force` пропускает клиентскую проверку.
- mstconfig 4.36.0: `--force set` отвергается **клиентом** («Unknown
  Parameter», RC=3; NVDA-write до FW не дошёл) — обход force в гейтах
  FW-поддержки появился только в 4.37.0.
- mstconfig 4.37.0 (контейнер `mlxini-mstflint-437`): **FW ПРИНЯЛ запись** —
  `--force set LC_NV_PUB_KEY_EXP=65537` → RC=0 (реальный NVDA SET,
  `mlxcfg_tlv.cpp:1106`; гипотеза «отказ ICMD» опровергнута). Post:
  обычный `q` — по-прежнему «doesn't support» (read-бит NVQC не поднялся),
  `--force q` → значение хранится и читается форсированно.
- До ребута: `LC_NV_PUB_KEY_UUID` = 32 hex-нуля ⇒ **провижинированного
  ключевого материала на карте НЕТ**; `0_255/256_511` читаются (raw-дампов
  нет: `get_raw` после чтения шлёт MFRL SET reset-prep,
  `mlxcfg_generic_commander.cpp:1076-1101` — не чистый read). Ребут: карта
  построчно идентична базлайну (GA SECURED / SB Capable Enabled / GUID-MAC /
  link UP); EXP=65537 **пережил reboot** (хранится в NV), семантически
  нейтрален.
- Полный тестовый RSA-4096 (sha256(pub.der)=`86469ed4…`, UUID
  `86469ED45026B4E30A27C0531AE61956` = первые 16 Б sha256(pubkey),
  modulus 512 Б BE; синтаксис BYTES — hex без 0x, длина кратна 8,
  `mlxcfg_param.cpp:1298-1329`) записан одной командой (`--force set UUID
  0_255 256_511`) — **FW принял без валидации** (RC=0; EXP не затёрт —
  read-modify-write TLV 0x19c); **пережил reboot**, карта построчно
  идентична базлайну, семантических эффектов ноль (EFUSE 0, dmesg чист).
- **CX-5**: TLV 0x19c–0x19e существуют на FW 16.35 (та же клиентская
  скрытость, `--force q` → RC=0); «хвоста подписи» в NVRAM нет — UUID=0,
  EXP=0, PSID_LOCK=0 заводски; полный тестовый RSA-4096 (UUID
  `6202D086…A246`) принят без валидации, пережил reboot сервера, эффектов
  ноль. В `mstflint q` CX-5 полей Life cycle/SB Capable нет вовсе (плоскость
  MGIR недоступна).

**Итог серии: NV-слоты lifecycle-ключей на GA SECURED (и CX-5) — пассивное
хранилище**: запись полного pubkey не активирует trust-anchor и не даёт ни
одного видимого эффекта. Активация — не NV-записью: иная плоскость
(lifecycle-state/MGIR/OTP и/или подписанный sign-сервером
provisioning-флоу — DB: «UUID is created by the sign server»). Тест-ключи
остались на картах (демонстративно инертны); откат — перезапись нулями
(решение владельца).

## 4. E-fuse-поверхность в публичном тулчейне 4.37 — отсутствует

Ключевой e-fuse-поверхности для CX-5 нет: `mstefuse` = trim-фузы напряжений
switch-ASIC (MRFV только в switch-layouts); единственный CX5-«EFUSE» в
mstflint — CR `0xf0c0c` → bin_speed (SKU-грейдинг, `mflash.c:1930`); MFVS —
только anti-rollback счётчик; 512-бит MDK из CR — BlueField-only
(`bluefiled_signature_manager.cpp:58`). Поддерживает гипотезу «e-fuse =
маркетинг»: anchor CX-5 — либо mask ROM, либо непубличный заводской прожиг
(`030-root-of-trust.md`, постулаты).

## 5. Прочие security-смежные NV-TLV

- `nv_psid_lock` (0x210) — публичные `PSID_LOCK` / `PSID_LOCK_MINOR`.
- `NV_ROM_ROOT_CA_FINGERPRINT` (0x197, target EXP_ROM, 32 Б, скрыт) —
  «Trusted private root certificate fingerprints» для option ROM.
- `file_public_key{,_4096,_4096_a,_4096_b}` / `file_signature*`
  (0x004/0x00b-0x00e/0x015) — скрытые параметры, документирующие структуру
  KEY VAULT/подписей (секции 0xa3/0xa6/0xa7); per-key флаги назначения —
  `015-key-sections.md` §3 (auth_cfg).
- Прочее: `nv_forbidden_versions` (= `flint set_forbidden_versions`),
  `nv_dpa_auth` (DPA_AUTHENTICATION), `nv_crypto_conf`
  (CRYPTO_POLICY/DATA_CRYPTO_ENGINE — data-at-rest), `nv_host_sync_conf`
  (ICMD-семфор/VSEC expulsion), `safe_mode_conf`.

## Постулаты / открытое

- [постулат] Семантика неполного ключа (только EXP, без modulus/UUID) и
  механизм активации lifecycle-механики (полный набор + sign-сервер?) — не
  проверялось (write-ветка 3 — решение владельца).
- [постулат] Гипотеза «активация требует полного набора (UUID + 512 Б
  modulus)» — не проверялась.
