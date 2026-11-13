# 170. Подпись образа: практические ответы (3 способа)

> Источник: чтение OSS mstflint `refs/src/mstflint` (CLI, strap-описания,
> 2026-09); live-актуализация циклов burn-digest (2026-10-28, non-secure
> CX-5 01:00.0) и securefw-gates (2026-10-29, `CARD_HPE_CX516A`).
> Связи: механизм/секции/CLI → `docs/250-re/110-signing/005-mechanism.md`,
> `…/015-key-sections.md`, `…/020-cli.md`; root-of-trust →
> `…/030-root-of-trust.md`;
> рецепты secure-fw карты (self-signed, FNP-once, чтение) →
> `180-securefw-recipes.md`; live-гейты →
> `docs/750-exp/170-securefw-live-gates.md`; FNP/кросс-флеш →
> `100-cross-flash-ops.md`.

## 1. Примет ли карта signed/unsigned образ

- **non-SB-карта** (`Security Attributes: N/A`): принимает **оба** —
  digest-only (unsigned) и RSA-signed; подпись для неё — просто лишние
  данные (live: карта работает на образе с битой RSA —
  `docs/750-exp/160-hpe-cx5-vpi-gen4-precheck.md` §10.5; plain burn со
  свежим дестом — `docs/750-exp/170-securefw-live-gates.md` §5).
- **secure/SB-карта**: верификация подписи безусловна (MCC FSM,
  `docs/250-re/110-signing/030-root-of-trust.md`); чужой/свой ключ без
  установки вольта → reject (0x7 uuid-not-found / 0x5 RSA-mismatch —
  `docs/250-re/110-signing/045-error-branches.md`). Судьба «своего ключа»
  зависит от поколения (вопрос закрыт с расщеплением, `030` §3): CX-5
  secure_fw — **да** после одной FNP-установки своего вольта
  (`180-securefw-recipes.md` §2); CX-6Dx GA SECURED — **нет** для бута
  (`docs/250-re/110-signing/055-cx6dx-signing.md` §6).
- Вывод для кросс-флеша: на non-SB-картах «unsigned/signed» неважно; на
  secure-картах — база OEM-семейства + self-signed вектор (`180` §1) или
  FNP-путь вендора (`100-cross-flash-ops.md` §9.1).

## 2. Три способа подписать свой образ (команды)

```sh
# 1) plain digest (как stock) — без ключа:
mstflint -i img.bin sign

# 2) RSA-подпись всего образа (свой ключ, свой uuid):
mstflint -i img.bin --private_key priv.pem --key_uuid <uuid> sign

# 3) secure-boot (свой ключ + свой публичный ключ в образе):
mstflint -i img.bin --private_key priv.pem --public_key pub.bin --key_uuid <uuid> rsa_sign
```

Важно: `keypair_uuid` в подписи должен совпасть с UUID публичного ключа,
вписанного в `0xA1/0xA4/0xA6` (`docs/250-re/110-signing/015-key-sections.md`).
Для **non-SB-карты**
этого достаточно (подпись не проверяется); для **SB-карты** — нет (нужен
корневой ключ Mellanox или установка своего вольта, `180` §1–§2).

Питфолл `sign` vs `rsa_sign`: `sign` c ключом подписывает только FW-update
(`0xA3`, SignForFwUpdate) и молча оставляет `0xA7` стейл (rc=0, без `-E-`);
`rsa_sign` делает SignForSecureBoot (`0xA7`) + SignForFwUpdate. Для
full-package SS-образов — только `rsa_sign` (отловлено parity-гейтом,
цикл cx6dx-introspection task-07; детали — `180` §1 шаг 4).

Контент-модифицированный образ на non-secure карте: достаточно пересчитать
plain digest способом (1) — FW-гейт проверяет именно его
(`docs/750-exp/170-securefw-live-gates.md` §5); pre-burn-чек —
`mstflint -i <img> sign` идемпотентен (md5 до/после равны; различие → STOP,
«забыли sign при сборке?»).

## 3. Что делает FNP (вендорский поток)

`FNP` — **аппаратный strap-пин** (read-only), бит `0x0.31` strap-регистра
(`tools_layouts/reg_access_hca_layouts.h:313-316`, «fnp strap»). FNP =
«Flash Not Present» — вендорский канон (MFT docs, «Booting HCA device in
livefish mode»: карта с отсутствующей/пустой флешей поднимается в
livefish/recovery); в общинных материалах встречается глосс «Factory New
Product» — та же семантика «карта как с завода». Открывает заводской
поток (программирование PSID, factory-калибровка). Это
**не** про подпись как таковую: в контексте перепрошивки FNP — обходной
путь вендора для смены PSID/перепрограммирования, когда обычный
`--allow_psid_change` недоступен (кейс восстановления CX6-Dx
Facebook→stock — `100-cross-flash-ops.md` §9.1). FNP-приём = решение ROM
при boot (джампер или битая/пустая флеша) — софтверного триггера recovery
нет (`docs/750-exp/170-securefw-live-gates.md` §2).
