# 035. FS4: hashes table (SHA-512 ITOC-секций)

> Источник: mstflint `mlxfwops/lib/fs4_ops.cpp`, `mlxfwops_com.h:124-127`,
> `flint_base.h:283`; эмпирика 2026-09-11 — локальный корпус (приложение).
> HW-CRC записей HW-указателей (правило приёма ptr-entry) — `025-crc.md` §5.

FS4-образ **может** содержать **hashes table** — таблицу хешей (SHA-512)
ITOC-секций.

## 1. Локация

Не DTOC-секция (тип 0xFB в enum есть, в FS4-флоу не используется). HW
pointers mstflint читает по **фиксированному offset образа `0x18`**
(`FS4_HW_PTR_START`, `flint_base.h:283`, `fs4_ops.cpp:286`) — 16 × 8B
entry (ptr u32 + crc) carmel layout (`image_layout_hw_pointers_carmel`,
`image_layout_layouts.h:594-660`): `hashes_table_pointer` = entry 15 →
байты **0x90 (ptr u32) / 0x94 (crc)**. Валидна, если ptr ≠ 0 и ≠
0xFFFFFFFF (`isHashesTableHwPtrValid`, `fs4_ops.cpp:5150-5160`); CRC
entry принимается по SW-CRC/HW-CRC-правилу (`025-crc.md` §5).

## 2. Структура

`GetHashesTableSize` `fs4_ops.cpp:5099-5124`, `HTOC` `fs4_ops.cpp:5649-5730`,
константы `mlxfwops_com.h:124-127`:

```
[hashes table header, 12B]
  +0x00 load_address  u32 (= 0)
  +0x04 dw_size       u32 (payload DW + 1)
  +0x08 crc           u16 — CRC-16 по первым 2 DW (lower-16 3-го DW)
[HTOC header, 16B]
  +0x00 version        u32
  +0x04 num_of_entries u8
  +0x05 hash_type      u8
  +0x06 hash_size      u16  (SHA-512 → 64)
[entry × N, 8B каждый]
  DW: lower-16 = hash_offset (отсчёт от HTOC base), bits 16-23 = section_type
[hash × N, hash_size байт] — после ВСЕХ entries;
  hash i @ htoc_base + 16 + N*8 + i*hash_size
[tail, 8B] — data CRC-16 по всем DW таблицы кроме последнего,
  lower-16 последнего DW
```

N (максимум) = 28 (`MAX_HTOC_ENTRIES_NUM`), **64 если version==1**
(`MAX_HTOC_ENTRIES_NUM_VERSION_1`); `HTOC_HASH_SIZE = 64`
(`mlxfwops_com.h:127`). Размер таблицы = `12 + 16 + N*(8 + hash_size) + 8`.
HTOC base = ptr + 12.

## 3. Верификация и обновление (mstflint)

- **Верификация** (`FsVerifyAux`, `fs4_ops.cpp:951-993`, при
  `q`/`verify`/`b`): только при валидном ptr — header CRC (12B) и data
  CRC (вся таблица). **Сверки хешей секций с таблицей в mstflint нет.**
- **Обновление** (`UpdateSectionHashInHashesTable`, `fs4_ops.cpp:3364`,
  вызов из `WriteSection` :4032): только при валидном ptr + секция
  **ITOC (не DTOC)** + тип не в {0xA0 SIG_256, 0xA1 PUB_KEYS_2048, 0xA3
  SIG_512, 0xA4 PUB_KEYS_4096, 0xA7 FS4_RSA4096_SIGS}
  (`IsSectionShouldBeHashed`, `fs4_ops.cpp:3344-3362`): SHA-512 данных
  секции → `htoc_base + entry.hash_offset` (entry нет → новый:
  `hash_offset = 16 + N*8 + idx*hash_size`, `num_of_entries++`,
  `AddNewEntry` `fs4_ops.cpp:5676-5713`); data CRC пересчитывается,
  header 12B — нет.

## 4. CX-7 (28.x): таблица зашифрована (2026-11-10)

> Источник: цикл cx7-boot-crypto task-04 (журнал
> `docs/superpowers/journal/2026-11-10-cx7-boot-crypto-task-04.md`,
> включая fix-round `fefaf32`); сводка — `051-fs4-cx7-encrypted.md` §8.

На CX-7 (FB 28.34.4000 live и 28.50.1002 дистрибьютор — оба класса
образов) hashes-table @0x15000 **зашифрована с байта 0**, включая 12B
header:

- экстент **0x804 = 12 + 16 + 28×(8+64) + 8** — ровно канон-размер §2
  при N=28 → layout тот же, но парсинг по plaintext-канону невозможен;
  «hdr CRC NG» текущего тулинга на CX-7 — именно это (CRC считается по
  шифротексту). `GetHashesTableSize` в encrypted-ветке HTOC не парсит —
  константы + комментарий `fs4_ops.cpp:5099-5124` (особо :5106).
- режим: additive-stream семейство (CTR/GCM-класс). ECB-shared-key / XTS
  (любые tweak-политики) / CBC-same-IV опровергнуты частичностью
  затронутых 16B-блоков: 11/32 блоков с диффами — частичные (4/16, 12/16,
  15/16 ненулевых), 12 равных lead-байтов внутри блоков — несовместимо с
  блочным лавинным эффектом.
- классы keystream: у сборок дистрибьютора 28.50.1002 keystream общий
  per-build — кросс-SKU диффы ровно в 7 hash-слотах + tail-CRC (8 прогонов
  = 447/2052 B, остальное байт-идентично; диффы декодируются как
  изменения pt-полей соответствующих секций SKU); у live FB-слотов
  шифротекст таблицы **A == B** (второй keystream-класс, отличный от
  билдового — ср. per-burn enc-ITOC, `051` §8.1).
- что хешируется: plaintext ITOC-секций (25 hashable ≤ 28; skip-набор §3
  соблюдается) → после расшифровки таблица — второй оракул целостности
  plaintext-секций; офлайн до ключа неюзабельна.
- ptr @0x90 на live CX-7 валиден → mstflint `q`/`verify` таблицу не
  пропускает (в отличие от эмпирики приложения ниже) и честно фейлится
  по CRC шифротекста — ожидаемое поведение, не повреждение.

## Приложение: эмпирика ptr (байт 0x90), 2026-09-11

| Образ | ptr |
|---|---|
| CX-5 16.35.1012 ADA `.bin` (factory) | 0xFFFFFFFF |
| CX-5 Dell 16.27.6120 `.signed.bin` | 0xFFFFFFFF |
| EDA 16.35.4030 `4030_eda_ri.bin` | 0xFFFFFFFF |
| CX-6Dx 22.50.1002 `.signed.bin` | 0x0 |
| live-дампы D1–D4, `e0_pre_raw.bin` | 0xFFFFFFFF |

→ во всех локальных образах (CX-5/CX-6 factory/signed/live-дампы) ptr
невалиден, mstflint **пропускает** hashes-проверку; hashes table **не
является** блокатором модификации device-data-секций. Реальный блокатор —
mDevInfo (INSECTION CRC + правило единственного валидного экземпляра) —
`docs/750-exp/140-post-fnp-guid-desync.md` §8.5/§8.7.
