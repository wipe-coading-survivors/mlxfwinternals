# 030. Подпись: выводы для инструмента (mlxfwutil)

> Источник: циклы burn-digest (2026-10-28, non-secure CX-5 — безусловный
> FW digest-гейт plain-burn) и securefw-gates (2026-10-29, secure-fw
> `CARD_HPE_CX516A`); модели подписи — mstflint `refs/src/mstflint`
> (fs3_ops/fs4_ops, 2026-09). Это спецификация инструмента (mlxfwutil):
> только факты и правила.
> Связи: ini/0x30 — `010-ini-mapping.md`; патч-матрица CRC —
> `020-patch-matrix.md`; алгоритм digest/маски —
> `docs/250-re/110-signing/010-payload.md`; команды подписания —
> `docs/250-re/110-signing/020-cli.md` и `docs/850-howto/170-signing-practical.md`;
> live-гейты — `docs/750-exp/170-securefw-live-gates.md`.

## 1. Digest 0xA0: пересчёт при контент-изменении — обязателен для MCC-пути

- При инжекте ini подписи/ключи **не трогаем**, но любое контент-изменение
  образа делает дест `0xA0` **стылым**: plain (MCC) burn на non-secure
  карте проверяет его безусловным FW-гейтом (код 0x2 на стылом) → дест
  **пересчитывается при сборке** (`mlxfwutil.py sign`; бит-эквивалент
  `mstflint -i <img> sign` без ключей; алгоритм/маски —
  `docs/250-re/110-signing/010-payload.md`).
- `--no_fw_ctrl` (direct path) дест **не проверяет** — там пересчёт не
  обязателен.
- Pre-burn-чек идемпотентности: повторный `sign` не меняет файл (md5
  до/после равны; различие → STOP, «забыли sign при сборке?»).

## 2. PSID/name/desc — в IMAGE_INFO

Смена = `--allow_psid_change`-логика (`docs/850-howto/100-cross-flash-ops.md`
§5); на secure-fw картах — только FNP-путь (§9.1 там же).

## 3. SB-карты: ограничение инструмента

Для SB-карт `mlxfwutil` без корневого ключа Mellanox бесполезен — это
ограничение, не баг. Уточнение по поколениям
(`docs/250-re/110-signing/030-root-of-trust.md` §3):
CX-5 secure_fw принимает SS-образы после одной FNP-установки своего вольта
(«FNP once → plain onwards», рецепт
`docs/850-howto/180-securefw-recipes.md` §2); CX-6Dx GA SECURED — SS не
бутается (`docs/250-re/110-signing/055-cx6dx-signing.md` §6). Полные
self-signed сборки — не
миссия mlxfwutil (могу только верифицировать/сравнивать).
