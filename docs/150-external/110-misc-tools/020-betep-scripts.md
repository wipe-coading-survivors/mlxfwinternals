# 020. BeTeP `mft-scripts`: `fs2_update_ini.py` / `mfa_extract.py`

> Источник: обход чекаута `refs/src/BeTeP-STH_mft-scripts` (два скрипта +
> README, 2026-11-07, журнал
> `docs/superpowers/journal/2026-11-07-restructure-external-task-03.md`);
> перенос 30 §5–6 (статический разбор 2026-09-06; верифицированное
> дополнение 2026-10-24). Репо: только `fs2_update_ini.py`,
> `mfa_extract.py`, `README.md`. Rev `4d88ae2` @ 2020-06-07, файла
> лицензии нет — `../000-pinned-revs.md`.
>
> Связи: FS2/GPH-формат — `docs/250-re/100-formats/010-fs2.md`; CRC-16 —
> `…/025-crc.md`; ini-маппинг (FS3/4, та же логика) —
> `docs/550-poc/100-mlxfwutil/010-ini-mapping.md`; сводка расхождений
> сторонних тулов — `../100-mstflint/010-walkthrough.md`.

Роли: `fs2_update_ini.py` — источник GPH-парсера для Rust-тула (фаза 2,
CX-2/FS2); `mfa_extract.py` — **не ядро** (наш скоуп — raw `.bin`, не MFA).

## 1. `fs2_update_ini.py` (174 строки, класс `FS2Image`)

Замена ini и PSID в готовом FS2-образе. Карта возможностей:

| Возможность | Где | Суть |
|---|---|---|
| GPH-заголовок | `:18` | `GPH_STRUCT = '>IIII'` — type/size/param/next, BE, 16B; размер секции `size*4+16` (`:82`, size в DW) — формат-факты в `010-fs2` |
| Типы секций | `:21` | `GPH_TYPES`: UNKNOWN DDR CNF JMP EMT ROM GUID BOARD_ID USER_DATA FW_CONF IMG_INFO DDRZ HASH_FILE LAST |
| TLV IMG_INFO | `:96-113` | `parse_imginfo`: пары tag/size, тег PSID → `psid_offset` |
| ini → FW_CONF | `:151-164` | `zlib.compress(ini, 9)` + выравнивание до 4; пересборка хвоста от FW_CONF (type 9): GPH `(9, len//4, 0, 0xff000000)` + zipped + CRC |
| PSID → IMG_INFO | `:145-147` | `set_psid`: TLV-запись по `psid_offset` + пересчёт CRC секции |
| CRC образа | `:119` | `crc16` — whole-image CRC-16 `0x100B`, поле @ `FS2_CRC_OFF = 0x22` (`010-fs2`, `025-crc`) |

Константы: `FS2_BOOT_START = 0x38`, `LASTNEXT = 0xff000000`,
`ZLIB = b'\x78\xDA'`.

Вердикт (30 §5): GPH-парсер **портируем в Rust** для CX-2/FS2 (фаза 2);
логика ini/PSID — та же, что FS3/4 (`010-ini-mapping`).

## 2. `mfa_extract.py` (88 строк)

Распаковка `.mfa` → `.bin` по PSID: магия `MFAR` (`:54`); 3 секции
(`>B2xBI4s` @ 16; сжатие определяется по xz-магии `\xFD7zX`, `:60`),
распаковка LZMA (`LZMADecompressor`, memlimit `0x10000000`); MTOC —
`parse_mtoc` (`:39`, per-PSID: part-number, desc, offsets); `.bin`
вырезается из blob-секции по `(off, size)` (`:69-72`) и показывается
через **mstflint subprocess** (`v`/`q`, `:73-74`; тестировалось с
mstflint 4.6.0). Уточнение против 30 §6: `import zlib` есть (`:11`), но
zlib не используется — распаковка только LZMA/xz.

Вердикт (30 §6): **не ядро** — работаем с raw `.bin`; отложить,
пригодится, если понадобится распаковка `.mfa`.

## 3. `.mfa` / `.mlx`: что это на самом деле (дополнение 2026-10-24)

Источник: репорт
`docs/superpowers/reports/2026-10-15-mlxburn-ini-binary-mapping.md` §4/§6.

- Гипотеза «fs2_update_ini патчит исходники, из которых тулчейн
  пересобирает образ» — **опровергнута**: пересборки нет.
- `.mfa` — дистрибутивный контейнер готовых `.bin` (MFAR + LZMA MTOC +
  blob); sources внутри не ездят.
- fs2_update_ini заменяет в готовом `.bin` ini-**тень** (FW_CONF zlib =
  то, что показывает `dc`) + PSID TLV + CRC — cross-flash-косметика,
  не конфиг-смена.
- Функциональный конфиг — бинарные поля (CNF/ROM/PLL), которые `mic`
  раскладывает по `TEMTParameters` из `.mlx` при **вендорской** сборке;
  клиентского «скрытого mic» не существует.
- Perl-секции `.mlx` — маппинг-метаданные (bitfield-хэши/CR-пути/
  `peval()`), не микрокод.
- Инвентарь refs: настоящие vendor-`.mlx` — только CX-2/CX-3
  (`refs/fw/Update_HP_0F60000010_…/fw-ConnectX{2,3}-rel.mlx`, XML с
  `TEMTParameters`); `refs/fw/cx-4/`, `cx-5-6/mlx-*/ri-*.mlx` — ri-дампы
  (магия `MTFW`), не пакеты.
