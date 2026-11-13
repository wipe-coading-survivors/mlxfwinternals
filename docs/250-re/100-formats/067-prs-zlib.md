# 067. PRS и секция 0x30 (DBG_FW_INI): zlib, dc-эквивалентность, флаги образа

> Источник: из 90 §3 (дополнительное независимое исследование, 2026-09-06);
> статический разбор OSS mstflint `refs/src/mstflint@a2b9858b`:
> `flint/subcommands.cpp:6809+` (`DcSubCommand`), `:6851` (`FwGetSection`),
> `mlxfwops/lib/flint_base.h:372` (`FS3_DBG_FW_INI = 0x30`); эмпирика —
> Dell-образ `09FTMY_071C1T` (rel 16_27_6120). Перепроверено по чекауту
> 2026-11-07.
> Связи: тип секции 0x30 в enum → `020-fs3-sections.md` §2; цепочка
> .prs→ini→0x30 и tool-side маппинг → `docs/550-poc/100-mlxfwutil/010-ini-mapping.md`
> (§1); «0x30 не функционален при boot» → `docs/550-poc/100-mlxfwutil/020-patch-matrix.md`
> §3 (строка .ini); флаги IMAGE_INFO vs состояние карты →
> `../110-signing/015-key-sections.md` §4 и `../110-signing/065-secure-fw-bit.md`;
> `dc` в процедуре кросс-флеша →
> `docs/850-howto/100-cross-flash-ops.md` §2.

TL;DR (из 90 §0.3): вывод `mstflint dc` = zlib-распаковка секции **0x30
(DBG_FW_INI)** внутри образа. PRS — *текстовый артефакт сборки*; рантайм
читает **бинарную** FW_MAIN_CFG (0x12), а не PRS.

## 1. `dc` = zlib(секция 0x30)

- `DcSubCommand` (`flint/subcommands.cpp:6809+`): «Print … the FW
  configuration text file used by the image generation process. This command
  would fail if the image does not contain a FW configuration section»;
  секция берётся `FwGetSection(FS3_DBG_FW_INI=0x30)` (`:6851`;
  `flint_base.h:372`). Нюанс диспетчера: для **FS2** `dc` читает GPH-секцию
  `H_FW_CONF` (9), не 0x30 (`:6851`, тернарник по `FwType()`).
- Данные 0x30 — zlib-поток (без пред-свора слов; маг `78 DA` — также
  `040-fs4-domains.md` §2 для 0x30/0x32/0x33).

## 2. Верификация байт-в-бит (Dell 09FTMY, 16_27_6120)

ITOC-запись `[21] 0x30 DBG_FW_INI @0x430e2c size=0xbf4` →
`zlib.decompress(буфер)` = **16556 байт** — в точности
`/tmp/09FTMY_071C1T-dc.txt`; заголовок: «Generated automatically by iniprep
tool … from ./cx5_dell_2p_100g.prs;; FW version: 16.27.6120». (Независимое
подтверждение цепочки на MCX4121A —
`docs/550-poc/100-mlxfwutil/010-ini-mapping.md` §1.)

## 3. PRS — инпут image-generation, не рантайм-конфиг

PRS-текст (то, что вываливает `dc`) — *инпут* image-generation; рантайм
читает бинарные секции конфигурации (FW_MAIN_CFG 0x12 и пр. —
`docs/550-poc/100-mlxfwutil/020-patch-matrix.md` §1/§3). Патч бинарного
конфига PRS-текст не трогает:
изменение сжатого 0x30 меняет размер секции → релокация образа; контроль
патча — байтом или живым линком, не по `dc` (правило зафиксировано
инструментом `scripts/probes/patch_56g.py`; каталог —
`docs/550-poc/100-mlxfwutil/040-probes-catalog.md`).

## 4. Флаги `[image_info]` PRS — это IMAGE_INFO, не MGIR

PRS `[image_info]` Dell-образа несёт `mcc_en=1`, `signed_fw=1`,
`secure_fw=1` — флаги **образа** (байт 2 DWORD[0] IMAGE_INFO —
`../110-signing/015-key-sections.md` §4), отдельно от карточного MGIR
(`../110-signing/065-secure-fw-bit.md`). Флаги образа — не индикатор и не
переключатель (`../110-signing/015-key-sections.md` §4).
