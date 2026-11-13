# 010. `cx5_gen4_enable.py`: разбор и сверка (FS4)

> Источник: сверка скрипта
> `refs/src/Mellanox-ConnectX-5-PCIe-Gen-4-Enablement/cx5_gen4_enable.py`
> с парсерами mstflint (исследование форматов образов, 2026-09/10) +
> статический разбор 30 §4 (2026-09-06); объединено при переносе 2026-11.
> Скрипт (627 строк): парсит ITOC, патчит байты PCIe-конфига (cap index,
> max speed, port gen, speed tables), пересчитывает CRC. Rev `ca701eb`,
> лицензия MIT — `../000-pinned-revs.md`. Ключевые строки: `:41`,
> `:45-56`, `:212-233`, `:253-303`, `:288`, `:335-353`.
>
> Связи: ITOC-записи и типы секций (семантика size/gap, relative_addr) —
> `docs/250-re/100-formats/020-fs3-sections.md`; CRC-16 — `…/025-crc.md`;
> FS4-ядро, ITOC Dell signed @ 0x4000 — `…/030-fs4.md`; чип→формат —
> `…/060-chip-map.md`; сигн-секции и crcf=1 —
> `docs/250-re/110-signing/015-key-sections.md`; сводка расхождений
> сторонних тулов vs mstflint — `../100-mstflint/010-walkthrough.md`;
> hwpointers-способ локации ITOC (наш выбор) —
> `../120-syndicate/010-mlx5fw-mlx5cmd.md`.

## Что брать (решения 30 §4.1)

- **`mlx_crc16`** (`:212`) — word-BE CRC-16: poly `0x100B`, init
  `0xFFFF`, сдвиг MSB (`word >> 31`), +16 нулевых бит, финальный XOR
  `0xFFFF` — совпадает с `calc_crc16_words` (irisc) и идентичен циклу
  mstflint (`Crc16::add`, проверено побитово; docstring скрипта сам
  ссылается на `mft_utils/crc16.cpp`); не путать со стандартной
  byte-wise-реализацией «по параметрам» — расхождение при init≠0
  (`025-crc`).
- **`fix_all_crcs`** (`:288`) — после правки секций пересчитывает
  section-CRC (над `data[flash_addr:end_addr]`) и entry-CRC (над
  `entry[0:28]`); сигн-секции `0xA0/0xA3` пропускаются (`:290`) —
  совпадает с crcf=1 у секций подписи (`015-key-sections`). Логика
  «правь секцию → пересчитай CRC секции + записи + ITOC» — переносится.
- **Офсеты полей** (проверены по образам):
  - `device_id = 0x1000 | FW_BOOT_CFG+0x002D` (`:335`);
  - `subsystem_id = FW_BOOT_CFG+0x003D` (`:336`);
  - `PSID = IMAGE_INFO+0x24..0x3C` (`:338`) — работает для FS4;
  - `port1_gen = HW_MAIN_CFG+0x0245`, `port2_gen = HW_MAIN_CFG+0x0285`
    (`:350-351`);
  - `cap_index = FW_BOOT_CFG+0x0093`, `max_speed = HW_BOOT_CFG+0x0023`
    (`:352-353`).
- size = 24-бит BE @ 0x01-0x03 = 22 бита size (биты 8-29) + 2-битный
  reserved-gap (биты 30-31) — для FS4-образов работает, т.к. gap = 0 в
  наших образах (gap — НЕ хвост param0; семантика — `020-fs3-sections`).

## Что НЕ брать (баги/ограничения, 30 §4.2)

1. **ITOC хардкод @ 0x5000** (`:41`) — работает для MCX512A/CX-6Dx,
   ломается на Dell signed (ITOC @ `0x4000`, `030-fs4`) и на FS3
   (ITOC @ `0x2000`). mstflint ищет; в `mlxfwutil` ITOC — по hwpointers
   (`toc.ptr + 0x20`, `120-syndicate/010` §1), не хардкод.
2. `flash_addr = BE u32 @ 0x14` (`:268`) — полный u32 без маски,
   включает бит 160; в FS4 он неиспользуем (0), поэтому работает.
   Совпадает с irisc-расхождением, **не** с mstflint (29 бит + маска
   бита 160). Общий парсер обязан брать `(b0x14 & 0x7F) << 24 | …`
   (в FS3 бит 160 = relative_addr). Полная таблица расхождений —
   `../100-mstflint/010-walkthrough.md`.
3. Не обрабатывает: header `num_of_entries` (0x17), FS4 entry version
   (0x10-0x11), DTOC, FS3-формат целиком (скрипт — **только FS4**),
   per-line CRC MAIN_CODE (не трогает MAIN_CODE — ок).
4. Не трогает header CRC — правильно (заголовок не меняется), но при
   изменении size/адресов записей entry-CRC скрипт пересчитывает — ок.
