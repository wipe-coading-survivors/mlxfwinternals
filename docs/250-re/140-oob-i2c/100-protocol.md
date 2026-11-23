# 100. Out-of-band I2C: проводной протокол CR-доступа и верхнеуровневые последовательности (Q1–Q5)

> Источник: цикл mtusb-i2c-re (2026-11-19), task-01 (§1–§6) и task-02
>   (§7–§9) — аудит
>   `refs/src/mstflint@a2b9858b59196c0d9a2224ac8ebcd86292f9abef` (пин —
>   `150-external/000-pinned-revs.md`; все file:line ниже — по этому пину,
>   если не указано иное; kernel-факты — `refs/src/linux/linux` @
>   `d135ab453a74`, тот же пин-файл); task-03 (§10) — мануалы
>   (`refs/docs/ethernet-adapters-programming-manual.txt`,
>   `refs/docs/nvidia-firmware-tools-mft-documentation-v4-29-0.0.txt`;
>   ссылки PRM:/MFT: — см. преамбулу §10); task-04 (§11) — свитчи (Q4,
>   pinned refs: код + MFT-doc); task-05 (§12) — офлайн-эмпирика
>   фрейминга: i2c-сборка mstflint (сиблинг mstflint-container, build-SHA
>   `1b8ac4b5` + патч-серия v4.37.0-1.4) против LD_PRELOAD-стаба. Номер
>   дока согласован с владельцем 2026-11-19. Статус: **final** (цикл 1
>   закрыт 2026-11-19: офлайн-канон — вердикты кодовые/мануальные,
>   фрейминг байт-уровневый и подтверждён офлайн-эмпирикой на стабе §12;
>   пункты, требующие живой шины, промаркированы как live-цикла 2 —
>   §6-таблица, §9.3, §10.4, §12.5 — до проверки остаются гипотезами).
>   Критерии закрытия спеки цикла выполнены (сверка — журнал task-06):
>   Q1–Q5 канонизированы (§2–§4, §7–§11), эмпирика внесена (§12),
>   транспортная спека написана —
>   `superpowers/specs/2026-11-19-mtusb-i2c-transport-design.md`,
>   роадмап-тик — отдельным коммитом. Состав: §1 «Транспорт и активация»; §2 «Проводной
>   протокол» (таблицы транзакций mread4/mwrite4/блоки/probe); §3 «Смена
>   secondary-адреса» (побайтово); §4 «Вердикт: адресное пространство»; §5
>   «Матрица поколений»; §6 «Передача»; §7 «mflash/ICMD поверх i2c» (регистры
>   flash-GW, busy-poll skip, ICMD-init, MCC-вердикт); §8 «Минимальные
>   последовательности» (open/q/dump/burn/restore); §9 «Ветвление записи»
>   (матрица Q5 + вердикт); §10 «Электрика/подключение» (Q3: PRM-цитаты,
>   MTUSB-1-модель, pin-факт, live-список, требования для Task 6); §11
>   «Свитчи» (Q4: код-улики в i2c-путях, MFT-doc-практика, вердикт); §12
>   «Эмпирическая валидация» (подтверждения, транскрипты,
>   расхождения/уточнения).
>   Журналы: `superpowers/journal/2026-11-19-mtusb-i2c-re-task-01.md`,
>   `…-task-02.md`, `…-task-03.md`, `…-task-04.md`, `…-task-05.md`,
>   `…-task-06.md` (финал/передача).
>   Связи: арка — `010-roadmap/120-mtusb-i2c.md`; спека цикла —
>   `superpowers/specs/2026-11-19-mtusb-i2c-re-design.md` (§2 Q1–Q5);
>   спека транспорта (деливерабл цикла 1, вход циклов 2–3) —
>   `superpowers/specs/2026-11-19-mtusb-i2c-transport-design.md`;
>   врезка MTUSB/I2C и смежные гейты — `110-signing/070-vpd-secure-state.md` §4
>   (перепроверена, расхождений нет); FNP/H-ROM-контекст (почему по PCI
>   mask-ROM не читается и что даёт out-of-band) —
>   `110-signing/025-secure-boot.md`; secure-fw классификация — `050` §2;
>   burn-флаги mstflint — `850-howto/100-cross-flash-ops.md` §6;
>   транспорт CH341/347 (live-стадия) — сиблинг `ch341i2c-container`.

## 1. Транспорт и активация

- **Имя → тип**: `mtcr_parse_name`: `strstr(name, "/dev/i2c")` → `MST_DEV_I2C`
  (`mtcr_ul/mtcr_ul_com.c:3052-3057`); MType `MST_DEV_I2C = 0x1000`
  (`include/mtcr_ul/mtcr_com_defs.h:296-297`); открытый девайс получает флаг
  `MDEVS_DEV_I2C = 0x200` (`mtcr_com_defs.h:334`; выставление
  `mtcr_ul_com.c:2805`).
- **Сборочный гейт**: весь i2c-блок mtcr под `#ifdef ENABLE_MST_DEV_I2C`
  (`mtcr_ul_com.c:2455`, закрывающий `:3011`); в configure опция выключена по
  умолчанию — `default_en_i2c="no"` (`configure.ac:88`). Т.е. сток-сборка
  mstflint i2c-бэкенда не содержит: `/dev/i2c-N` распарсится как неизвестное
  имя (парсер :3052 внутри `#ifdef`).
- **Открытие**: `mtcr_i2c_open` (`mtcr_ul_com.c:2799-2828`): fd =
  `open(name, O_RDWR | O_SYNC)` (:2813); `dtype` принудительно `MST_TAVOR`
  (:2804, «ensure correct address_width»); vtable
  mread4/mwrite4/mread4_block/mwrite4_block = i2c-функции (:2808-2811);
  затем смена secondary-адреса (§3). Диспетч open: `mtcr_ul_com.c:4105-4113`.
- **Вызовы**: публичные `mread4/mwrite4/mread4_block/mwrite4_block`
  (`mtcr_ul/mtcr_ul.c:44-62`) → `*_ul` → vtable `ul_ctx`
  (`mtcr_ul_com.c:312-323`, `:3224-3235`).
- **Энумерации нет**: `mdevices_v_ul` сканирует только
  `/sys/bus/pci/devices` и гейтит `if (!(mask & MDEVS_TAVOR_CR)) return 0`
  (`mtcr_ul_com.c:3392-3395`) — i2c-девайс можно только открыть по явному
  имени. Легаси-флаг `MDEVS_I2CM` (0x02, интерфейс-тип SDK `MTUSB`/`NDC`,
  `mft_sdk/mft_sdk_discovery.cpp:248-250`) — вестиг без бэкенда (070 §4,
  подтверждено).
- **Протокол драйвера**: только ioctl `I2C_RDWR` на fd `/dev/i2c-N`
  (rg по mtcr: ни `I2C_SLAVE`, ни `I2C_TENBIT`, ни PEC — нуль попаданий).
  Семантика Linux: один ioctl = combined-транзакция из N сообщений
  «without stop in between» (`Documentation/i2c/dev-interface.rst:127-128`;
  repeated START вместо STOP между сообщениями —
  `Documentation/i2c/i2c-protocol.rst:41-50`). `i2c_msg.addr` — 7-битный
  slave-адрес; флаг `I2C_M_RD` — направление второго сообщения.
- **Идентификаторы для реализации**: slave по умолчанию **0x48**
  (`mtcr_ul_com.c:2806`), secure-gen функциональные — **0x47** (§3);
  адрес CR-регистра — 4 байта big-endian (§2); данные — dword'ы big-endian
  (§2).

## 2. Проводной протокол (таблицы транзакций)

Общие свойства всех транзакций: slave-адрес 7-бит (`i2c_msg.addr` =
`mf->i2c_secondary`); адрес CR и данные — big-endian; успех mread4/mwrite4 =
возврат 4; ошибка ioctl (`rc < 0`) → возврат −1, errno i2c-dev пробрасывается
вызывающему (`mtcr_ul_com.c:2651-2657`, `:2687-2693`); **ретраев, таймаутов и
NACK-обработки в mtcr-слое нет** (единственный retry-цикл — смена sec-addr,
§3). Энкодер адреса — `prepare_i2c_buf` (`mtcr_ul_com.c:2584-2613`), для
mstflint-флоу всегда 4-байтовый BE32-вариант (dtype `MST_TAVOR`, :2804).

### 2.1 mread4 — чтение dword (`mtcr_i2c_mread4`, `mtcr_ul_com.c:2624-2663`)

Один ioctl `I2C_RDWR`, 2 сообщения (combined: между msg повторный START,
без STOP):

| # | slave | flags | len | байты | смысл |
|---|-------|-------|-----|-------|-------|
| msg[0] | 0x48/0x47/override | 0 (write) | 4 | `BE32(offset)` | адрес CR-регистра, полный 32-бит BE, без маски |
| msg[1] | тот же | `I2C_M_RD` | 4 | ← данные | значение регистра, BE32 (сборка `BYTES_TO_DWORD_BE`, `common/compatibility.h:394-399`) |

Пример wire (чтение 0xf0014; BE32-адрес = `00 0F 00 14`):
`S 0x90 W A 00 0F 00 14 A Sr 0x91 R A D3 D2 D1 D0 NA P`
(0x90 = 0x48<<1|W; 0x91 = 0x48<<1|R; D3 — старший байт значения).

### 2.2 mwrite4 — запись dword (`mtcr_i2c_mwrite4`, `mtcr_ul_com.c:2665-2698`)

Один ioctl `I2C_RDWR`, 1 сообщение:

| # | slave | flags | len | байты | смысл |
|---|-------|-------|-----|-------|-------|
| msg[0] | 0x48/0x47/override | 0 (write) | 8 | `BE32(offset) ‖ BE32(value)` | адрес + значение, оба BE |

### 2.3 mread4_block — блочное чтение (`mtcr_ul_com.c:2457-2486` → `mread_i2c_chunk` `:2488-2503` → `mread_i2cblock` `:2702-2748`)

Разбиение на чанки **64 Б** (`MAX_TRANS_SIZE = 64`, `mtcr_ul_com.c:71-73`;
цикл `mtcr_i2c_mread_chunks:2466-2479`, offset += 64 за итерацию). На каждый
чанк — один ioctl `I2C_RDWR`, 2 сообщения (combined):

| # | slave | flags | len | байты | смысл |
|---|-------|-------|-----|-------|-------|
| msg[0] | sec | 0 (write) | 4 | `BE32(offset_чанка)` | адрес первого байта чанка |
| msg[1] | sec | `I2C_M_RD` | N ≤ 64 | ← данные | N байт начиная с offset; внутри чанка код адрес больше не шлёт — **требуется автоинкремент указателя у slave** (подразумевается кодом, отдельно не подтверждается) |

Payload-дворды BE → host (`fix_endianness` `:2501`, реализация `:2556-2575`).
Гейт: N > 64 → `EINVAL` (`:2706-2710`). Ошибка чанка → вернуть суммарно
прочитанное (`:2471-2475`).

### 2.4 mwrite4_block — блочная запись (`mtcr_ul_com.c:2506-2537` → `mwrite_i2c_chunk` `:2539-2554` → `mwrite_i2cblock` `:2751-2788`)

Разбиение на чанки **32 Б** (`MAX_CHUNK_SIZE = 32`, `mtcr_ul_com.c:68`;
цикл `mtcr_i2c_mwrite_chunks:2516-2529`, offset += 32). На каждый чанк — один
ioctl `I2C_RDWR`, 1 сообщение:

| # | slave | flags | len | байты | смысл |
|---|-------|-------|-----|-------|-------|
| msg[0] | sec | 0 (write) | 4 + M, M ≤ 32 | `BE32(offset_чанка) ‖ BE32(payload[0]) ‖ … ` | адрес + M байт данных; дворды BE (`fix_endianness` `:2541` — на LE-хосте конвертирует in-place, **мутирует буфер вызывающего**, код-деталь) |

Внутри чанка промежуточные адреса не шлются — автоинкремент slave (как §2.3).
Гейт в `mwrite_i2cblock` — `length > MAX_TRANS_SIZE` (64, `:2755-2759`);
буфер 64+4 (`:2770`); чанкование выше всегда режет по 32.

### 2.5 probe dev-id (`read_device_id`, `mtcr_ul_com.c:5456-5495`)

Транзакция ≡ §2.1 по адресу `mf->cr_space_offset + HW_ID_ADDR`, где
`HW_ID_ADDR = 0xf0014` (`:134`), а `cr_space_offset` для i2c всегда 0
(`update_device_cr_space_offset:188-202` — ненулевой (`0x3000000`,
`GPU_NETIR_CR_SPACE_OFFSET:53-54`) только для GPU-девайсов с `dinfo`, который
в i2c-пути не заполняется). Разбор ответа: `dev_id = dword & 0xffff`,
`rev_id = биты [16:20)` (`EXTRACT(*device_id, 16, 4)`, `:5474-5475`).

### 2.6 Варианты энкодера адреса (`prepare_i2c_buf`, `mtcr_ul_com.c:2584-2613`; width↔dtype `:5561-5599`)

| dtype (`mtcr_com_defs.h:315-321`) | байт адреса | код |
|---|---|---|
| `MST_TAVOR` (дефолт i2c-open) | 4, `BE32(offset)` полный | `:2588-2593` |
| `MST_GAMLA` (=MST_EEPROM) | 2, `BE16(offset & 0xffff)` | `:2595-2601` |
| `MST_DIMM` | 1, `(u8)(offset & 0xff)` | `:2603-2608` |
| прочее (`MST_NOADDR`) | 0 — msg[0] становится read-фазой, nmsgs=1 | `:2610-2612`; ветки `:2644-2650` (mread4), `:2734-2739` (block) |

В mstflint-флоу i2c всегда TAVOR/4 байта: open фиксирует dtype (`:2804`), а
`mread/mwrite_i2cblock` лишь восстанавливают его из текущего
(`mget_i2c_addr_width`, `:2492`, `:2545`; смена `mset_i2c_addr_width`
невалидной шириной → `EINVAL`, `:2712-2716`).

## 3. Смена secondary-адреса (`change_i2c_secondary_address`, `mtcr_ul_com.c:2939-3010`)

Дефолт 0x48 («Livefish devices and non-secure generation functional
devices», `:2806`). **На проводе смена адреса не существует** — это выбор
клиентом `i2c_msg.addr` следующих транзакций; сами проверки — только probe
§2.5 (никаких write-транзакций; гипотеза спеки «PMC-запись?» — исключена).
Пошагово (все шаги — T5-транзакции §2.5):

1. **Override**: выставлен `force_i2c_address` → `mf->i2c_secondary =
   force_i2c_address`, выход без проб (`:2955-2959`). Источники force —
   flint `--i2c_secondary` (`flint/flint.cpp:280-285`, `set_force_i2c_address`
   `mtcr_ul_com.c:2577-2582`) и SDK `mstGetDeviceHandleWithI2cSecondary`
   (`mft_sdk/mft_sdk_discovery.cpp:581-593`). Runtime-смена без force —
   `mset_i2c_secondary` (`mtcr_ul_com.c:5601-5615`; потребители: mstdump
   `mstdump/crd_main/mstdump.c:175-182`, mcra `small_utils/mcra.c:325-327`).
2. probe@0x48; нечитается (≠4) → отказ open (`:2962-2965`).
3. `dev_id@0x48` ∉ `supported_device_ids` (таблица `:2836-2884`) →
   `try_to_read_secure_device` (`:2915-2937`): `mf->i2c_secondary = 0x47`
   (`:2920`), probe@0x47; id ∈ `secured_devices` → успех (0x47), иначе
   отказ.
4. `dev_id@0x48` ∈ supported и ∉ secured → **остаёмся на 0x48** (livefish и
   non-secure-gen функциональные; `:2973-2976`).
5. `dev_id@0x48` ∈ **secured** (`secured_devices`, `:2830-2832`: CX7 0x218,
   CX8 0x21e, CX9 0x224, CX8-PurePCIeSwitch 0x222, QTM2 0x257, QTM3 0x25b,
   CX9-PurePCIeSwitch 0x228, NVLink6-Switch 0x278; значения —
   `dev_mgt/tools_dev_types.h:141-173`): функциональный девайс secure-gen
   ответил на 0x48 → `mf->i2c_secondary = 0x47` (`:2978`), probe@0x47;
   нечитается → отказ (`:2981-2984`); `dev_id@0x48 ≠ dev_id@0x47` →
   retry-цикл **до 100 итераций × 10 мс** до совпадения (`:2991-3004`).
   Интерпретация расхождения id на двух адресах (переходное состояние при
   переключении livefish→функциональный) — гипотеза: код комментарий не даёт.
6. Код-деталь: обе функции под `#if !defined(__VMKERNEL_UW_NATIVE__)`
   (`:2917`, `:2941`; закрывающий `:3007-3009`) — в ESX/VMKernel-сборке
   проверки пропускаются, адрес остаётся 0x48.

## 4. Вердикт: адресное пространство (произвольный 32-бит CR-адрес vs окно)

**По коду — произвольный 32-битный адрес, без окна.** В i2c-пути offset
(`unsigned int`) сериализуется целиком (`prepare_i2c_buf` BE32,
`mtcr_ul_com.c:2588-2593`); масок, границ и диапазонных проверок нет ни в
`mtcr_i2c_mread4/mwrite4`, ни в block-функциях (`:2624-2699`, `:2457-2554`,
`:2702-2788`). Контраст с остальными транспортами: pcicr гейтит окно
`MTCR_MAP_SIZE` 0x4000000 (`:647`, `:685`), pciconf/driver-ioctl несёт
отдельное поле address_space (`:866-868`; enum `AS_CR_SPACE` и др.,
`mtcr_com_defs.h:377-387`) — i2c-фрейминг селектора пространства не имеет:
32-битный offset и есть весь адрес.

Что декодирует сам i2c-slave (какое подмножество CR реально отвечает) —
свойство HW/FW конкретной карты/поколения, OSS-кодом не видно. Для H-ROM
(спека цикла §2: чтение mask-ROM в FNP по I2C) вывод: протокол не запрещает
адресовать любые 0x00000000–0xffffffff; фактическое покрытие ROM-области —
live-проба цикла 2.

**[live 2026-11-22, цикл 2 T6 FNP]** Фактическое декодирование ограничено
(уточнение этого вердикта): известные регистровые окна отвечают реальными
данными (0xf0014 dev-id; GW-блок 0xf0400-0xf0420 — живые регистры,
когерентные нашим же операциям); ВНЕ их — дегенератные служебные паттерны,
не данные: (а) низкие адреса → адресный счётчик addr>>2 с dword-автоинкре-
ментом (0x0→0,1,2,3; 0x1000→0x400+; 0x2004→0x801+; 0x4000→0x1000+);
(б) регион 0xb97e00+/0xffff8000 → константный филл f7f930f3; (в) отдельные
окна → нули (0x1040000). Алиасинг верхних бит адреса (0x1001000==0x1000,
0x2000000==0x0; но 0x1040000≠0x4000 — маска не выводится однозначно).
H-ROM-вердикт (O7): mask-ROM на i2c-CR-адресах в FNP **не читается** —
все 13 проб (11 кандидатов phase-XIII + подтверждения) вернули служебные
паттерны, ни бут-векторов, ни кода, ни flash-зеркал (транскрипты — журнал
`2026-11-22-mtusb-i2c-hw-task-06.md` Phase G).

## 5. Матрица поколений (по коду)

Единственная точка, где код различает поколения в i2c-пути, — таблицы §3:

| Поколение (HwId) | supported (`:2836-2884`) | secured (`:2830-2832`) → sec-addr | Фрейминг §2 |
|---|---|---|---|
| CX-3/3Pro, IB, SX (0x1f5/0x1f7/0x1ff, 0x247/0x249) | да | нет → 0x48 | не различается по коду |
| CX-4/4LX (0x209/0x20b), BF1 (0x211) | да | нет → 0x48 | не различается по коду |
| CX-5/6/6DX/6LX (0x20d/0x20f/0x212/0x216), BF2/3 (0x214/0x21c) | да | **нет → 0x48** (secure-capable ген, но в secured-таблицу не входит) | не различается по коду |
| CX-7 (0x218) | да | да → 0x47 (§3 п.5) | не различается по коду |
| CX-8/9 (0x21e/0x224), CX8/9-PurePCIeSwitch (0x222/0x228), BF4 (0x224) | да | да → 0x47 | не различается по коду |
| QTM (0x24d) / Spectrum1-6 | да / да | нет → 0x48 | не различается по коду |
| QTM2/3 (0x257/0x25b), NVLink6-Switch (0x278) | да | да → 0x47 | не различается по коду |

Примечания: (а) `DeviceBlueField4_HwId = 0x224` совпадает по значению с
`DeviceConnectX9_HwId` (`tools_dev_types.h:155-160`) — по одному id из probe
они неразличимы, оба в secured; (б) cable-id (0x03/0x0d/0x11/0x19) входят в
supported-таблицу для кабельных pseudo-девайсов (`mtcr_cables`, исключено из
Q1 — журнал task-01), к NIC CR-пути отношения не имеют; (в) вне
`supported_device_ids` из hw-enum остаётся только `DeviceSpectrum6IB_HwId`
(diff enum `tools_dev_types.h:139+` против таблицы `:2836-2884`; GB100/GR100
в таблицу входят, `:2880-2881`) — такой id на 0x48 не пропускается
проверкой §3 п.3 и уходит на 0x47-пробу.

Фрейминг, чанки (64/32), эндриан, отсутствие ретраев — единый код для всех
поколений: иных поколенческих ветвлений в i2c-транспорте по коду нет.

**[live 2026-11-22, цикл 2 T6b]** Матрица live-подтверждена построчно
(журнал `superpowers/journal/2026-11-22-mtusb-i2c-hw-task-06b.md`):
таблица mtcr — **поколенческая**, и провод это подтверждает — 0x47-активность
следует за hw_id (∈ secured-таблицы), НЕ за секьюрити-стейтом карты:

| карта (functional) | hw_id (PCI CR) | секьюрити карты | ACK-адреса | данные @0x48 | данные @0x47 |
|---|---|---|---|---|---|
| CX-5 ACA [15b3:1017] (T2) | 0x020d | non-secured | 0x48, 0x1f | живые (0x20d, guard ≠0, полн. CR) | — (NAK) |
| CX-5 Ex Dell [15b3:1019] | 0x020d | **secure-fw** | **только 0x48** | **живые** (0x20d == PCI, guard ≠0) | — (NAK) |
| CX-6 Dx [15b3:101d] | 0x0212 | secure-fw | 0x48, 0x1f | **mute-нули** (ACK, данные 0; PCI CR 0x212 жив) | — (NAK) |
| CX-7 FB_ [15b3:1021] | 0x0218 | GA SECURED | 0x47, 0x48, 0x1f | mute-нули | **живые** (0x218 == PCI, gen6-guard 0xf0484/0xf0488 ≠0) |

Live-вердикты: (а) §3 п.5/§4-п.5 спеки закрыты — CX-7 functional отвечает
@0x47 полным регистровым файлом, 0x48 остаётся probe/mute-адресом; первое
combined-чтение @0x47 дало переходный мусор 0xc07fffff, второе — стабильный
0x218 == PCI (первое live-наблюдение того, что defensive retry-цикл §3 п.5
обходит; см. также §6-таблицу, строка §3 п.5); (б) mute @0x48 — свойство
поколений ≥6 (CX-6 Dx, CX-7), НЕ секьюрити-стейта (CX-5 Ex secure — живые
данные @0x48; driven-нули ≠ ff-подтяжке — слейв ведёт линию).
**Оговорка-конфаунд**: обе карты ≥6-го поколения в выборке — secure-fw,
non-secure CX-6 в лабе отсутствует — разделение «поколение vs секьюрити»
держится на единственной паре (CX-5 Ex secure: живые данные против
нулей CX-6 Dx/CX-7); что именно глушится (FW-политика gen6+?) — открытый
вопрос; (в) 0x1f-сосед
не универсален (CX-5 Ex — единственная карта без 0x1f); 0x1f-hang
воспроизведён на CX-6 Dx (n=2, генерации 5→6): одиночное combined-чтение →
оба слейва NAK ≥2 мин, БЕЗ 522 на PCI (i2c-only коллапс, FW/ICMD жив —
уточнение T2-эпизода); (г) нюанс: Dell CX-5 Ex [15b3:1019] CR HW_ID =
0x020d (i2c == PCI), вопреки §11-ожиданию 1019↔0x20e — открытое наблюдение.
Guard-примечание: 0xf0408/0xf040c — legacy/gen5-пара; для CX-7 (6gen)
живая guard-пара — 0xf0484/0xf0488 (§7.1), legacy-пара нулевая.

## 6. Передача (handoff)

- **Задача 2 (Q2, ICMD/mflash поверх i2c)** — выполнена, см. §7–§9: рег-канал
  `maccess_reg_ul` для не-IB идёт `mreg_send_raw` (`mtcr_ul_com.c:4747-4764`),
  ICMD-инициализация для `MST_DEV_I2C` — `icmd_open` → `icmd_init_cr`
  (`mtcr_ul/mtcr_ul_icmd_cif.c:1462-1467`); mflash busy-poll skip —
  `mflash/mflash.c:1166-1172`. Минимальные последовательности q/дампа/burn — §8,
  ветвление записи — §9.
- **Задачи 5–6 (T5 стаб, состав burn)**: таблицы §2 + транзакции §7.3 — вход
  для транзакционного стаба (границы FW-зависимости — §8.6); вердикт §4 — вход
  для H-ROM-пробы цикла 2.
- **Задача 4 (Q4, свитчи)** — выполнена, см. §11: транспортных ветвлений
  «свитч vs NIC» в i2c-коде нет; свитч-иды входят только в
  secured/supported-таблицы (§5); MFT-doc документирует switch reprogramming
  через MTUSB-1 с предварительным mux-роутингом (§11.2).
- **Задача 6 (транспортная спека)** — выполнена: спека транспорта
  `superpowers/specs/2026-11-19-mtusb-i2c-transport-design.md` (единая на
  арку: интерфейс транзакций, покрытие бэкендов CH341/CH347/generic,
  sec-addr, электрика из §10.5, операции M0–M3 по §8, euid-гейт §12.3-4,
  открытые пункты O1–O10); вход — требования электрики/подключения и
  MTUSB-модель §10 (перенесены в спеку без перечитывания мануалов).
- **Открытые пункты** (кодом не решаются — live-цикл 2). Явные поля
  «live-проба / доказало бы / опровергло бы» — дискриминаторы для цикла 2;
  статусы — колонка «статус» (обновлялась по ходу цикла 2: T2 — первое
  live-чтение CR; T3 — семафор GW + O6; T6 — FNP-дамп/O7/O9; T6b —
  матрица поколений; финальная сводка цикла — ниже; журналы
  `superpowers/journal/2026-11-2[12]-mtusb-i2c-hw-task-0*.md`):

  | пункт | live-проба (цикл 2) | доказало бы | опровергло бы | статус (цикл 2, финал 2026-11-22) |
  |---|---|---|---|---|
  | фактическое декодирование адресов slave'ом (§4) | чтение нескольких произвольных CR-адресов собственным мастером (вкл. ROM-область — live-кандидат H-ROM) | какое подмножество 32-битного пространства отвечает (границы окна; покрытие ROM) | универсальность «произвольный 32-битный адрес» (если вне окна ответа нет) | **закрыто (T6, 2026-11-22, FNP/livefish)**: известные регистровые окна декодируются (0xf0014; GW-блок, значения когерентны операциям клиента); вне окон — служебные паттерны (счётчик addr>>2 / филл f7f930f3 / нули) с алиасингом верхних бит; H-ROM (O7) не читается — подробности §4; в NORMAL (T2) вне GW-окрестности не проверено (0x1f-инцидент) |
  | природа расхождения dev-id@0x48 vs @0x47 в retry-цикле (§3 п.5) | наблюдение переходного состояния при переключении livefish↔функциональный | гипотезу переходного состояния | — (интерпретация, не код) | **частично (T6b, 2026-11-22, CX-7)**: первое combined-чтение @0x47 после адресных проб вернуло переходный мусор 0xc07fffff, второе — стабильный 0x218 == PCI — переходное состояние первого чтения наблюдено live (гипотеза поддержана, механизм не вскрыт); CX-5 non-secured: 0x47 не ACK'ает (T2), CX-5 Ex secure: тоже NAK (0x47-активность — поколенческая, §5 live) |
  | поведение NACK/тайминги на реальной шине (§2; mtcr ретраев не делает) | работа с живым slave: NAK-реакции, растяжение клока | нужен ли клиентский retry-слой транспорта | достаточность no-retry-семантики как есть | **частично**: все транзакции прошли с первого раза (retry не потребовался); латентностные полы честные (mread4 4.81 мс, blk16 10.21 мс, blk64 31.87 мс @20 кГц ≥ расчётных 4.5/9.9/31.5); НО после одного combined-чтения к соседу 0x1f слейвы карты замолчали (NAK на все адреса; карта функциональна, линии 3.2 В; оживление — только полный power cycle, re-plug мастера и mstfwreset (блокирован 522) не помогают). O5-вердикт: no-retry-семантика mtcr достаточна — ни одна транзакция успешных сессий T2–T6 не потребовала ретрая (0 спонтанных NACK на ~2,1 млн блоков двух полных дампов + PCI-контроли); единственный наблюдённый отказ-режим (0x1f-подвес) транспорту не подконтролен — лечится только power cycle карты, клиентский retry бессилен |
  | достаточность отсутствия busy-poll (§7.4) | чтение DATA сразу после Go (без пере-чтений CMD) на реальных таймингах | «латентность i2c ≥ готовность GW» | — (потребуется poll бита30) | **закрыто позитивом (T6, FNP)**: RDID + полный дамп 16 MiB исполнены без пере-чтения CMD между Go и DATA-чтением, 0 ошибок на 1 048 576 блоках (история: на функциональной карте T3 не проверяемо — семафор у живого FW) |
  | поведение flash-GW/ICMD на livefish-карте по i2c (§7.5 п.1, §9.3) | GW-семафор/RDID и ICMD-инициализация на livefish | живёт ли DFA/MCC поверх i2c в livefish | — (ожидание: GW залочен HW) | **закрыто позитивом (T6, FNP)**: ожидание подтверждено и преодолено — семафор при входе занят HW (bit31=1 стабильно; PCI-сторона видит то же `Can not obtain Flash semaphore`), канонический force-release (W CMD=0, T15-прецедент `--force-lock`) освобождает персистентно; далее полный GW-путь жив: RDID (jedec Winbond 16 MiB), дамп 16 MiB §8.2 (0 ошибок, 64.7 blk/s @100 кГц), PCI-rb той же карты байт-в-байт == i2c-дампу; GW-активность (записи DATA-окна) провоцирует re-assert семафора (журнал task-06 Phase B/C/H) |

  Live-факты T2 сверх таблицы (детали/транскрипты — журнал task-02):
  фрейминг §2.1 подтверждён байт-в-байт (первое вне-стаб свидетельство),
  dev-id §2.5 = 0x020d (ConnectX-5, rev A0 — арбитраж план/lspci закрыт),
  автоинкремент §2.3 подтверждён; сосед 0x1f ACK'ает, но combined-чтение
  к нему вернуло ff×16 и, вероятно, повесило FW карты (I2C-слейв замолчал
  + ICMD застрял (522), лечится ТОЛЬКО полным обесточиванием — re-plug
  мастера и mstfwreset (блокирован 522) не помогают; оба слейва 0x48/0x1f умирают и
  воскресают вместе, скоррелированы с питанием карты) — до идентификации
  0x1f не трогать. Матрица SFP (T2, финал): ACK@0x48 **не зависит** от
  наличия SFP-модуля/линка (IN/OUT/IN с контролем линка dmesg) —
  livefish-канал жив при operstate=down.

- **Сводка live-итогов цикла 2 (mtusb-i2c-hw, финал 2026-11-22; рецепт —
  `850-howto/200-oob-i2c.md`, O-статусы — спека транспорта §9):**
  - T1: электрика/распиновка (CH347T ZIF13=SCL/ZIF14=SDA/ZIF4=GND,
    continuity + ACK), honesty-гейт латентностей; CH341A исключён
    электрически.
  - T2: первое live-чтение CR — фрейминг §2.1 байт-в-байт, dev-id 0x020d,
    автоинкремент §2.3 подтверждён, guard-пара функциональной карты ≠0;
    0x1f-инцидент (правило «не трогать»).
  - T3: семафор GW на функциональной карте удерживается живым FW
    (провоцируется первым GW-областным чтением бута); ICMD-версия @0x0 = 1
    (O6, read-уровень); GW-путь на функциональной карте не гарантирован.
  - T5: cold-start lock — канон взятия GW-lock (poll-first
    самопоражается); W1 вариант 1 (кадр 26 Б как есть) DELIVERED; ZLP
    валит адаптер fw 5.44; O10-read (окно DATA@0xf0410 читается без Go).
  - T6 (FNP): семафор HW-held — force-release (T15-прецедент) решает
    персистентно для обеих сторон; RDID Winbond 16 MiB; полный дамп
    16 MiB — 0 ошибок, PCI-`rb` байт-в-байт (3-way: канон @100 кГц /
    packed @400 кГц 685.5 blk/s / PCI); O7 refuted (mask-ROM на
    i2c-CR-адресах не читается — §4); O9 closed; O10-write closed
    (нюанс: dword-квантование невыровненных CR-записей вниз).
  - T6b: матрица поколений §5 live-подтверждена (0x47 — поколенческая
    секьюрити-таблица, не стейт карты); 0x1f-hang воспроизведён
    кросс-поколенно (n=2); переходный мусор первого чтения @0x47.

  Осталось циклу 3: burn/restore поверх GW (записи во flash не исполнялись),
  O1/O3 спеки, ICMD-обмен, идентификация 0x1f.

## 7. mflash/ICMD поверх i2c (Q2)

Всё ниже — тот же mfile с vtable §1: любой MREAD4/MWRITE4/mread4_block/
mwrite4_block mflash/ICMD-слоя сериализуется транзакциями §2 (никаких
отдельных i2c-путей в mflash/ICMD нет). Единственная i2c-специфика — §7.4
(busy-poll skip) и §7.5 п.1 (инициализация ICMD).

### 7.1 Карта регистров flash-GW (direct flash access)

Диспетч: `mf_open_fw` (`mflash/mflash.c:3341-3432`): дефолт legacy-адреса
(:3351-3357); CX3-семейство (`IS_CONNECTX_4TH_GEN_FAMILY` = только
CX3/CX3Pro, `mflash_pack_layer.h:122`) → `cntx_flash_init`; иначе при
`is_icmdif_supported` (`mflash_dev_capability.c:119-166`) — по
`get_flash_gen` (`mflash_dev_capability.c:168-204`):

| Gen GW | девайсы | CMD | ADDR | DATA | DATA_SIZE | lock (семафор) |
|---|---|---|---|---|---|---|
| legacy | CIB, CX4/4LX/5/6/6DX/6LX, BF1/2, Quantum, SPC1-3 | 0xf0400 | 0xf0404 | 0xf0410 | поле в CMD, биты 8..10 (log2) | `connectib_flash_lock` (mflash.c:1904-1925) = `is4_flash_lock` (poll бита31 CMD + unlock-запись 0, mflash.c:1638-1695) + disable/restore cache-replacement |
| 6gen | QTM2, SPC4/5/6, CX7, BF3, Abir | 0xf0400 (дефолт) | 0xf0420 (`update_sixth_gen_addrs`, mflash.c:2407-2432) | 0xf0410 | поле в CMD, биты 8..12 (5 бит, `HBS_NEW_GW_DATA_SIZE`, mflash_pack_layer.h:396) | `sixth_gen_flash_lock` (mflash.c:1874) |
| 7gen | QTM3, NVL6, ArcusE (база 0x101000); CX8/CX8-PPS/CX9/CX9-PPS/BF4 (база 0x8a1000) (mflash_pack_layer.h:344-377; группы — mflash.c:2321-2376) | база+0 | база+0x3c | база+0x10 | **отдельный регистр** база+0x44 (`set_gw_data_size`, mflash_new_gw.c:83-90) | `seventh_gen_flash_lock` (mflash.c:1852) |
| CX3 (cntx DFA) | CX3/CX3Pro | 0xf0400 | 0xf0404 | 0xf0410 | поле в CMD (8..10) | `old_flash_lock` (mflash.c:1487-1562): SEMAP63 **0xf03fc** (mflash.c:170) + trm-ресурс для CX3 |

Константы legacy/6gen/7gen — `mflash_pack_layer.h:323-378`; поля CMD — там же
:381-409. Код-деталь: `update_seventh_gen_addrs` содержит также кейсы
Spectrum5/6 (mflash.c:2321, 2377-2392, у SPC6 — «агент1» 0x101080), но
`get_flash_gen` относит SPC4-6 к SIX_GEN (:173-182) — до 7gen-ветки они не
доходят (расхождение таблиц mstflint, на i2c не сказывается).
VSC-recovery-смещения GW (zombiefish, mflash.c:2328-2366,
`VSC_RECOVERY_SPACE_FLASH_GW_BASE_ADDRESS 0x10`, mflash_pack_layer.h:117) для
i2c недостижимы: `is_zombiefish_device` отличает только MST_PCI/MST_PCICONF
(`mtcr_ul_com.c:5441-5453`), для i2c всегда 0. Cache-replacement-регистры
(адреса по поколениям — mflash.c:1927-1936: legacy off/cmd 0xf0408/0xf040c,
gen5 0xf0444/0xf0448, gen6 0xf0484/0xf0488, pager 7gen HCA 0x8a1204/0x8a1208,
switch 0x101204/0x101208) — см. §8.3 п.0.

### 7.2 Формат командного слова flash-GW

Legacy (`HBO_*`, mflash_pack_layer.h:381-394; сборка — `cntx_exec_cmd`
mflash_gw.c:124-161): бит0 R/W (1=чтение), бит2 cmd-phase, бит3 addr-phase,
бит4 data-phase, бит5 CS-hold, биты8..10 data-size (log2 от байт), бит11
chip-select (= bank), бит14 addr-size (1 → 4-байтные SPI-адреса, ставится
автоматом при 4byte-наборе команд, mflash_gw.c:132-142), биты16..23 SPI-опкод,
бит30 busy (ставится ПОСЛЕДНИМ — Go), бит31 lock (для не-CX3 — всегда 1 при
команде, mflash_gw.c:126-131). 6/7gen (`HBO_7GEN_*` / `update_*_gen_addrs`,
mflash.c:2394-2404, 2410-2424): бит5 R/W, бит7/8/9 cmd/addr/data-phase, бит10
CS-hold, бит13 CS, бит15 addr-size, биты16..23 опкод, бит30 busy; lock-бит31
ставится всегда (mflash_new_gw.c:170). SPI-опкоды (`StFlashCommand`,
mflash_common_structs.h:103-141): READ 0x03 / 4READ 0x13, PP 0x02 / 4PP 0x12,
WREN 0x06, RDSR 0x05, SE 0xd8 / 4SE 0xdc, SSE 0x20 / 4SSE 0x21, RDID 0x9f,
RES 0xab. Примеры dword'ов (legacy, CS=0, 3-байтный адрес, lock+busy
выставлены; вычислены basecalc'ом, журнал task-02):

| операция | dword CMD |
|---|---|
| READ 16Б (первый+последний блок) | `0xC003041D` |
| READ 16Б (продолжение, CS-hold, без addr- и cmd-phase — биты 3/2 = 0) | `0xC0000431` |
| WREN | `0xC0060004` |
| PP 16Б (первый блок) | `0xC002041C` |
| RDSR (4Б чтение, `cntx_int_spi_get_status_data` mflash_gw.c:264-287) | `0xC0050215` |
| SE (sector erase) | `0xC0D8000C` |

### 7.3 Транзакции GW поверх §2 (byte-уровень)

Блочная единица mflash — `attr.block_write = 16` Б (mflash.c:993) → каждый
обмен данными = ровно один чанк §2.3/§2.4 (16 ≤ 64 read / 4+16 ≤ 32 write).
Общая обвязка `cntx_exec_cmd_get/set` (mflash_gw.c:175-262; new_gw-версии
mflash_new_gw.c:202-303 — та же структура):

**exec_cmd_set (запись блока, пример PP 16Б @flash_addr):**

| # | вызов | i2c-транзакция (поверх §2) |
|---|---|---|
| 1 | `mfl_com_lock` → lock-функция поколения (§7.1; legacy-ядро — `is4_flash_lock`) poll бита31 CMD + cache-rep RMW-пара @0xf0420 — §12.3-1 | цикл §2.1-read @0xf0400 до LOCK=0 (msleep 1 мс, mflash.c:1654-1680; предел — 1024 попытки, не «5 с» — уточнение в §7.4) + RMW-пара @0xf0420 (disable) |
| 2 | `mwrite4_block(DATA=0xf0410, 16Б)` | один §2.4-чанк: W `BE32(0xf0410)=00 0F 04 10 ‖ 16Б BE-двордов` (данные пакуются BE вручную, mflash_gw.c:417-427) |
| 3 | `mwrite4(ADDR=0xf0404, flash_addr)` | §2.2-write: `BE32(0xf0404) ‖ BE32(addr)` |
| 4 | `mwrite4(CMD=0xf0400, 0xC002041C)` | §2.2-write: `BE32(0xf0400) ‖ BE32(cmd)` — Go |
| 5 | `gw_wait_ready` | **пропущено для i2c** (§7.4) |
| 6 | `release_semaphore` → unlock | RMW-пара @0xf0420 (restore) + §2.2-write: `BE32(0xf0400) ‖ BE32(0)` (mflash.c:1684) |

Для блока-продолжения (CS-hold, `is_first=0`): п.3 (ADDR) не выполняется —
addr передаётся только при `is_first` (`cntx_st_spi_block_write_ex`
mflash_gw.c:398-409, 429; new_gw-версия mflash_new_gw.c:444-455, 476), в CMD
ставится CS-hold; данные (п.2) пишутся в каждом блоке.

**exec_cmd_get (чтение блока, пример READ 16Б):**

| # | вызов | i2c-транзакция (поверх §2) |
|---|---|---|
| 1 | `mfl_com_lock` → lock-функция поколения (та же, что set-п.1: poll бита31 CMD + cache-rep RMW-пара @0xf0420 — §12.3-1) | цикл §2.1-read @0xf0400 до LOCK=0 + RMW-пара @0xf0420 (disable) |
| 2 | `mwrite4(ADDR=0xf0404, flash_addr)` | §2.2-write: `BE32(0xf0404) ‖ BE32(addr)` |
| 3 | `mwrite4(CMD=0xf0400, 0xC003041D)` | §2.2-write: `BE32(0xf0400) ‖ BE32(cmd)` — Go |
| 4 | `gw_wait_ready` | **пропущено для i2c** (§7.4) |
| 5 | `mread4_block(DATA=0xf0410, 16Б)` | один §2.3-чанк: combined W `BE32(0xf0410)` → R 16Б |
| 6 | `release_semaphore` → unlock | RMW-пара @0xf0420 (restore) + §2.2-write: `BE32(0xf0400) ‖ BE32(0)` |

Для безадресных SPI-команд (RDID/RES/RDSR) п.2 (ADDR) не выполняется —
CMD не содержит addr-phase (§12.3-2, транскрипт s9: RDID `0xC09F0215`).
Для блока-продолжения мультиблочного чтения — CMD `0xC0000431` с CS-hold,
addr не повторяется (как в set). BE→host конверсия у вызывающего
(mflash_gw.c:538-541).

**WREN** (перед каждым PP/erase/WRSR, mflash_gw.c:288-299): полный цикл
lock → `mwrite4(CMD, 0xC0060004)` → unlock. **WIP-poll** (`st_spi_wait_wip`
mflash_gw.c:67-94): после erase — init 20 мс, затем RDSR-циклы (полный
exec_cmd_get с CMD=0xC0050215) каждые 300 мкс, ≤10000 попыток; после PP —
init 10 мкс + 1 мкс/Б, retry 10 мкс (`mflash_access_layer.h:87-94`);
критерий — бит0 RDSR-ответа == 0. **Erase** (`cntx_st_spi_erase_sect`
mflash_gw.c:338-366): set_bank → WREN → exec_cmd_set(CMD=0xC0D8000C или
`attr.erase_command`, addr = flash_addr & mask банка) → WIP-poll.

### 7.4 Busy-polling skip: что именно пропущено и что осталось

Пропуск — **только** цикл чтения CMD-регистра до снятия busy-бита30
(`gw_wait_ready`, mflash.c:1164-1198): для `tp == MST_DEV_I2C` немедленный
`MFE_OK` (:1166-1172). Обоснование кода: «FlashGW HW sends the SPI command
much faster than it takes the next transaction on i2c bus» (:1168) — т.е.
вместо опроса код полагается на латентность следующей i2c-транзакции (на
практике — латентность unlock-записи или чтения DATA). **Не пропущены**
(остаются i2c-транзакциями, все — поверх §2): (а) семафор-GW: poll бита31 и
unlock-запись нуля (§7.3 п.1/6); (б) WIP-poll через RDSR-команды GW (§7.3);
(в) cache-replacement guard (§8.3 п.0). Гипотеза о достаточности
(«i2c-медленнее SPI») на реальной шине — live-цикл 2 (§6).
  **[live 2026-11-21, цикл 2 T3]** На функциональной CX-5 не проверено:
  GW-семафор оказался удержан живым FW (CMD@0xf0400=0x80000000
  персистентно ≥50 с; lock-poll исчерпал свои 1024 попытки — см.
  уточнение ниже), GW-команды не исполнялись, записей ноль; O9 остаётся
  открытым (журнал `…-mtusb-i2c-hw-task-03.md`).
  **[уточнение 2026-11-22, цикл 3 T4-аудит]** «Таймаут 5 с» lock-цикла
  (`is4_flash_lock`, комментарий mflash.c:1654 «timeout at 5 seconds») —
  Windows-only: на Linux TIMER-макросы — no-op (`#ifndef __WIN__`,
  mflash.c:93-101), 5-с стенки не существует. Эффективный предел —
  счётный `GPIO_SEM_TRIES`=1024 попыток (mflash_access_layer.h:98):
  ≈1.1 с на PCI / ≈2.6 с на i2c (~2.5 мс/попытка), терминал тот же
  `MFE_SEM_LOCKED`. Касается формулировок §7.3 п.1 и §8.2 (заменено
  там). Журнал `2026-11-22-mtusb-i2c-impl-task-04.md`.

### 7.5 ICMD поверх i2c: инициализация и обмен

1. **Гейты `icmd_open`** (mtcr_ul_icmd_cif.c:1437-1493): для PCI-транспортов
   livefish/zombiefish → `ME_ICMD_NOT_SUPPORTED` (:1447-1450). Для i2c гейт
   **не срабатывает**: условие проверяет `is_pci_device(mf) || (flags &
   MDEVS_TAVOR_CR)`, а `is_pci_device` (:1409-1412) смотрит `MDEVS_I2CM`
   (0x02 — вестиг 070 §4) / cable / software; i2c-open ставит только
   `MDEVS_DEV_I2C` 0x200 (mtcr_ul_com.c:2805), TAVOR_CR не выставлен. Плюс
   `is_livefish_device`/`dm_is_livefish_mode` на i2c всегда 0: `dinfo` не
   заполняется (mtcr_ul_icmd_cif.c:1415-1417; tools_dev_types.c:968-973 —
   `!mf->dinfo → 0`). Код-следствие: ICMD-open по i2c идёт и на livefish-карте
   (для PCI — отказ); поведение FW там — live-цикл 2.
2. **Инициализация**: `icmd_open` → (MST_UL-сборка, `functional_vsec_supp`=0
   для i2c — VSEC не пробуется) → `tp == MST_DEV_I2C → icmd_init_cr`
   (:1462-1467) — та же CR-space-инициализация, что для MST_IB/GPU.
   `icmd_init_cr` (:1047-1256): read_device_id (§2.5) → таблица адресов по
   hw_id → `get_version` (чтение reg@hcr_address, биты 24..31, :344-354;
   версия должна быть 1, иначе `ME_ICMD_UNSUPPORTED_ICMD_VERSION`, :1240)
   → чтение cmd_ptr@cmd_ptr_addr (биты 0..23) → `cmd_addr`,
   `ctrl_addr = cmd_addr + 0x3fc`, `syndrome_addr = cmd_addr + 0x3f8`
   (:112-127, 1226-1234); `max_cmd_size = ICMD_MAX_CMD_SIZE 0x340`
   (mtcr_com_defs.h:41). Ключевые адреса (там же, :76-127):

| класс | hw_id примеры | semaphore | cmd_ptr / hcr(version) | static_cfg_not_done |
|---|---|---|---|---|
| CIB/CX4/CX5/CX6/BF1/2 | 0x209/0x20b/0x20d/0x20f… | CX4 0xe250c, CX5 0xe74e0 | 0x0 | CX4 0xb0004, CX5 0xb5e04, CX6 0xb5f04 |
| CX7/BF3/BF4 | 0x218… | 0xe5660 | 0x0 | 0xb5f04 |
| CX8/CX9 (+PPS) | 0x21e/0x224… | 0x57680 (358016) | 0x1a00000 (27262976; он же version-reg, version-биты 28+) | 0xa0304 (656132) |
| свитчи SW-IB/QTM | 0x247/0x24d… | 0xa24f8/0xa68f8 | 0x80000/0x100000 | 0x80010/0x100010 |

   **[live 2026-11-21, цикл 2 T3]** CX-5 (hw_id 0x20d): чтение
   @cmd_ptr/hcr=0x0 → dword 0x01002000 — версия (биты 24..31) = **1** →
   ICMD-интерфейс жив поверх i2c (O6-вердикт, read-уровень); cmd_ptr
   (биты 0..23 того же регистра) = 0x2000. Существенно: в том же
   состоянии карты PCI-ICMD давал 522 (застрявший FW-запрос), а
   версионная проба по i2c отвечала осмысленным значением (журнал
   task-03).

3. **Семафор** (`icmd_take_semaphore_com` :708-777): для i2c (не vsec) —
   попытка = read-цикл §2.1 @semaphore_addr, ожидание 0, затем (т.к.
   `is_gw_access`=0 — только BAR0-GW/VSEC, mtcr_ul.c:275-282)
   контрольное чтение: бит31 dword'а должен стать 1
   (`SEMAPHORE_62_LOCKED_INDICATOR`, :57, :752-766; на VSC/BAR0-GW семафор —
   целый dword, :275-280). Ретраи ≤256, `msleep(rand()%50)` (:770).
   Очистка — запись 0 (`icmd_clear_semaphore_com` :627-657, :653).
4. **Обмен** (`icmd_send_command_com` :814-911): icmd_open по требованию →
   check_msg_size (≤0x340) → `icmd_is_cmd_ifc_ready` (чтение
   static_cfg_not_done-бита) → take semaphore → `set_opcode` (RMW ctrl:
   чтение ctrl, opcode<<16, запись, :589-603) → `mwrite_buffer` данных в
   mailbox@cmd_addr (чанки §2.4) → check busy (бит0 ctrl == 0) → **Go**:
   set_busy_bit (запись ctrl с бит0=1, :365-369) → poll busy
   (usleep 10/100/1000 мкс по фазам; таймаут `MFT_ICMD_TIMEOUT`/дефолт,
   :494-584) → status = биты8..15 ctrl (таблица :431-462; 0x7 =
   `ME_ICMD_WRITE_PROTECT`) → при ошибке syndrome@+0x3f8 → `mread_buffer`
   ответа mailbox (чанки §2.3) → clear semaphore. Для i2c
   `mset_addr_space`-макросы (SET_SPACE_FOR_ICMD_ACCESS и пр., :186-196) —
   no-op (нет VSEC): весь обмен в одном 32-битном CR-пространстве,
   консистентно с вердиктом §4.
5. **Отличия от PCIe-инициализации** (`icmd_init_vcr` :1338-1377,
   functional-VSEC-путь): (а) адреса — VCR: mailbox 0x100000, ctrl 0x0,
   semaphore 0x0, размер из VCR_CMD_SIZE_ADDR 0x1000, syndrome 0x1008
   (:122-126); CR: см. таблицу выше (cmd_ptr косвенный); (б) семафор:
   vsec-путь пишет PID и сравнивает целый dword, i2c/CR-путь — бит31;
   (в) адресные пространства: vsec переключает AS_ICMD/AS_SEMAPHORE, i2c —
   нет. Сам протокол команд (opcode/Go/busy/status/syndrome) — идентичен.
6. **Reg-access (MGIR и все прочие)**: `maccess_reg_ul` (mtcr_ul_com.c:4707)
   → не-IB → `mreg_send_raw` (:4953-5029): Operation-TLV + Reg-TLV + payload
   (`init_operation_tlv`, :4962-4974) → `mreg_send_wrapper` (:4892-4951) →
   для i2c `icmd_send_command_int(FLASH_REG_ACCESS = 0x9001)`
   (:4926-4929; mtcr_com_defs.h:39). Идентификаторы: MGIR 0x9020, MFPA
   0x9010 / MFBA 0x9011 / MFBE 0x9012 (FW-flash доступ), MCQS 0x9060 /
   MCQI 0x9061 / MCC 0x9062 / MCDA 0x9063 (component update)
   (reg_access/reg_access.c:49-92).

### 7.6 MCC-семантика vs PCIe: вердикт

**По коду семантика MCC не изменяется.** Путь компонент-апдейта
(`FwCompsMgr`, fw_comps_mgr/fw_comps_mgr.cpp:1156-1191 — открывает тот же
`mopen(devname)`-девайс) полностью лежит на reg-access: MCQS/MCQI/MCC/MCDA
→ `maccess_reg` → ICMD 0x9001 → транзакции §2 (пример: `runMCQI`
fw_comps_mgr.cpp:867-903 → `reg_access_mcqi` reg_access.c:667-684).
Выбор «MCC vs direct flash access» (`FwOperations::Create`, fw_ops.cpp:960-1175)
ветвится по: флагам `noFwCtrl`/`ignoreCacheRep` (:982), успешности
FwCompsMgr/MCDA-capability (MCAM, :987-1026), `mccUnsupported && !
secure_fw` (:1035-1041; `mccUnsupported` выставляют flint для
-nofs/-apc/use_dev_rom, subcommands.cpp:2590-2593, 613), MLNX_OS BB-WA
(:1044-1078) — **транспорта в решении нет** (ни `MST_DEV_I2C`, ни `tp`, ни
flags-i2c в fw_ops.cpp/fsctrl_ops.cpp/fw_comps_mgr.cpp — нуль попаданий;
единственный tp-check — `tp == MST_IB` для inband, fw_comps_mgr.cpp:1062).
Следствие: по коду на i2c сначала пробуется MCC (ICMD поверх i2c), при
отказе/флагах — direct access (flash-GW §7.1–7.3). Практическая разница —
только латентность/надёжность транспорта; живёт ли MCC поверх i2c (FW
отвечает на 0x9001 по CR-адресам) — «доказывается циклом 2».

## 8. Минимальные последовательности (транзакционный уровень)

Общая прелюдия для всех операций — §1/§3: open `/dev/i2c-N` → probe dev-id
(§2.5; сценарии проб/смены sec-addr — §3) → далее по операциям. Каждая строка
ниже = i2c-транзакции §2 (сколько именно — см. §7.3/§7.5: GW-команда ≈ 3–5
транзакций, ICMD-команда ≈ 10–25 + чанки буфера).

### 8.1 `q` (open → identify → запросы)

1. `mopen` + смена sec-addr (§3) — probe @0x48 [→ 0x47].
2. `dm_get_device_id` (tools_dev_types.c:588-704): read_device_id @0xf0014
   (§2.5) → hw_id/rev. (На i2c `dinfo`-веток нет — MGIR-вариант только для
   MDEVS_MLNX_OS, :661.)
3. **Вилка MCC-vs-DFA** (fw_ops.cpp:982-1085; транспортонезависимая,
   решается ответами FW — граница для стаба):
   - MCC: FwCompsMgr-open → ICMD-init (§7.5) → MGIR 0x9020 + MCQS/MCQI
     (FsCtrlOperations::FwInit, fsctrl_ops.cpp:93+, 173) — каждая = ICMD
     0x9001: semaphore → opcode → mailbox → Go → poll → mailbox ← → sem 0.
   - DFA (MCC отвергнут): `FwAccessCreate` (fw_ops.cpp:580-594) → `Flash`
     → `mf_open_fw` (mflash.c:3341-3432): повторный read_device_id →
     выбор gen-инициализации (§7.1) → идентификация flash: RDID 0x9f /
     RES 0xab через GW-команды (§7.3; `cntx_spi_get_type`
     mflash.c:1311-1323, `get_flash_info_by_res` :674-699; CMD для RDID =
     0xC09F0215 по формуле §7.2) → далее FS3/FS4-разбор образа —
     чтения flash §8.2.
4. Вывод `q` собирается из fw_info (версии/GUIDs/PSID — из MGIR в MCC-пути
   или из образа в DFA-пути). **Граница FW**: стаб без FW увидит шаги 1–3
   до первого mailbox-обмена (MCC) или jedec-чтения (DFA), дальше —
   таймауты/ошибки.

### 8.2 Дамп (`ri`/`rb`)

`Flash::read` → `mf_read` → `read_chunks` (mflash.c:1066-1156) → по
16-блокам `cntx_st_spi_block_read_ex` (mflash_gw.c:489-543; 6/7gen —
`new_gw_st_spi_block_read_ex`, mflash_new_gw.c:535-589, тот же каркас):

1. Семафор: poll CMD@0xf0400 бит31 → 0 (§7.3 п.1).
2. mwrite4 ADDR@0xf0404 = BE32(addr&bank_mask).
3. mwrite4 CMD@0xf0400 = 0xC003041D (READ, первый блок; продолжение мульти-
   блочного чтения — 0xC0000431 с CS-hold, addr не повторяется).
4. busy-poll — пропуск (§7.4).
5. mread4_block DATA@0xf0410, 16Б (один §2.3-чанк).
6. Unlock: mwrite4 CMD = 0. → следующий блок.

Шагов 1–6 по 16Б на весь образ; никаких FW-команд (чистый GW-путь) —
**единственная FW-граница**: сам семафор/GW может быть залочен живым FW
(тогда poll п.1 идёт до `MFE_SEM_LOCKED` — предел 1024 попытки ≈2.6 с
на i2c, не «5 с»: см. §7.4-уточнение). Для `ri` MCC-путь не
используется (mflash всегда direct). `rb addr size` — те же §8.2-шаги на
заданный диапазон flash; `dc`/CR-чтения — голые §2.1-транзакции, без
GW/ICMD вовсе.

### 8.3 Burn — direct access (SPI GW)

Обвязка `Flash::write` (flint_io.cpp:694-805): `mf_acquire_persistent_lock`
(mflash.c:2120-2133 — см. §9.2 п.1 про unlock_blocked на i2c) → по
выравненным чанкам: erase сектора → `mf_write` → release. Секции пишет
`BurnFs3Image` (fs3_ops.cpp:1197-1356): [boot+itoc без сигнатуры → itoc-
секции (skip `device_data` при failsafe/!useImgDevData, :1318-1339) →
сигнатура ПОСЛЕДНЕЙ, :1346-1354]; `BurnFs4Image` (fs4_ops.cpp:2613-2776):
все itoc-секции образа (:2706-2724), dtoc+device-data при `useImgDevData`
(:2726-2776), сигнатура через signature-manager (:2782+). Транзакционно:

0. **Cache-replacement guard** (mflash.c:2034-2118, для 5/6/7gen при
   инициализации): чтения cache-rep/pager-регистров (по поколению,
   :2067-2098); если off/cmd ≠ 0 → burn уходит в FW-путь (MFBA) либо
   требует `-ocr` (тогда — `mwrite4(0xf0014, 0)`, :2114, сброс read-only
   HW_DEV_ID ради cache replacement). Это единственная точка, где burn
   может молча сменить транспорт обмена (на FW-регистры 0x9011/0x9012
   через ICMD §7.5), — по FW-состоянию, не по i2c.
1. Persistent lock (семафор §7.3 п.1, но не отпускается до конца write —
   flint_io.cpp:723-729, 799-803).
2. На каждый сектор: erase = WREN-команда (lock→CMD 0xC0060004→unlock) →
   SE-команда (lock→ADDR→CMD 0xC0D8000C→unlock) → WIP-poll (RDSR-команды
   каждые 300 мкс, ≤10000).
3. На каждый 16Б-блок данных: (первый — WREN) → lock → DATA(16Б) → ADDR →
   CMD 0xC002041C → unlock; последний блок серии → WIP-poll (10 мкс+1 мкс/Б,
   retry 10 мкс).
4. Сигнатура (16Б) — обычный write с noerase (fs3_ops.cpp:1351).
5. `DoAfterBurnJobs` (fs3_ops.cpp:4532+): обновление boot-адреса и
   инвалидация сигнатуры старого образа (запись нуля @0) — те же GW-записи.
   Сброс/активация карты — вне flint (mstfwreset/хост); i2c-веток для reset
   в mstflint-коде нет.

Verify после burn (`FwVerify`): повторные §8.2-чтения и сравнение с образом
(fs3_ops.cpp/fs4_ops.cpp, `VerifyCallBack`-механика) — транспортонезависимо.

### 8.4 Burn — MCC (component update)

Если выбран MCC (§7.6): всё через ICMD 0x9001 — MCQS (query status) →
MCC (lock component / download / burn / activate — FSM,
fw_comps_mgr.cpp:800-865) → MCDA/MCDI (данные) → MCC (activate) → MCQS
(poll). Транзакционно — только §7.5-команды; **стаб увидит** semaphore/
opcode/mailbox/Go-обмены, содержимое mailbox — TLV §7.5 п.6. FW-граница
полная (каждый шаг зависит от ответа FW).

### 8.5 Restore

Отдельного код-пути нет: restore = `burn` из файла-дампа (FImage-вход,
`FwAccessCreate` fw_ops.cpp:474-483). Последовательность ≡ §8.3/§8.4.

### 8.6 Границы FW-зависимости (вход для стаба Task 5)

Стаб без FW корректно отработает: open+probe+sec-addr (§1/§3), read_device_id
(ответы stab'а), GW-регистры-записи (§7.3 — команды уйдут, busy-poll нет),
ICMD-init-чтения (§7.5 п.2). Остановится/потребует заглушек на: GW-семафоре
(п.1 poll — нужен ответ 0), jedec/RDSR (данные от «flash»), ICMD-семафоре и
mailbox-Go (статусы FW), cache-rep-регистрах (§8.3 п.0). Для MCC-пути весь
поток после первого MCQS — FW-зависим; для DFA-пути данные читаются/пишутся
GW-транзакциями без FW-участия (кроме семафора).

## 9. Ветвление записи (Q5)

### 9.1 Матрица «операция × ветвление × транспорт»

| точка ветвления | пин | влияет на {список секций; порядок; write-protect/SKIP; verify} | ветвление по транспорту? |
|---|---|---|---|
| busy-poll skip | mflash.c:1166-1172 | нет (только ожидание готовности GW) | **да** (i2c-only), поведение §7.4 |
| ICMD-init по tp | mtcr_ul_icmd_cif.c:1462-1467 | нет (адреса инициализации; выбор CR vs VCR) | **да**, семантика команд не меняется (§7.5 п.5) |
| `--i2c_secondary` force | flint.cpp:280-285 | нет | да (адрес slave §3) |
| MCC-vs-DFA выбор | fw_ops.cpp:982-1085 | **да**: состав записи (компоненты vs сырые секции), механизм protect (MCC-FSM vs GW+WREN) | **нет** — решают флаги/ответы FW (§7.6) |
| skip `device_data` секций (FS3) | fs3_ops.cpp:1318-1339 | да (список секций) | нет (burnParams: failsafe/useImgDevData) |
| dtoc/device-data (FS4) | fs4_ops.cpp:2668-2676, 2726-2776 | да (список секций) | нет (useImgDevData) |
| сигнатура последней | fs3_ops.cpp:1346-1354 | да (порядок) | нет |
| `_no_burn` skip записи | flint_io.cpp:755-758 | да (SKIP записи) | нет — мёртвый глобал без сеттера (flint_base.cpp:68; в дереве 3 хита: def/extern/use) |
| `-nofs/-apc/use_dev_rom` → DFA | subcommands.cpp:2590-2593 | да (список секций/механизм) | нет (флаги CLI) |
| cache-replacement guard | mflash.c:2034-2118 | да (уйти в MFBA/потребовать -ocr) | нет (состояние FW) |
| zombiefish recovery-GW | mflash.c:2328-2366 | да (адреса GW) | нет по коду: на i2c `is_zombiefish_device`≡0 (mtcr_ul_com.c:5441-5453) |
| unlock_blocked (persistent lock) | mflash.c:2120-2133 | нет (семантика семафора: держать между write-опами) | **косвенно**: ветвится по `dinfo==NULL` (i2c), не по tp — §9.2 |

### 9.2 Вердикт по гипотезе владельца («I2C пишет больше секций, чем PCI»)

**Код-уровень: не подтверждается.** Write-пути (flint_io/fs3/fs4/fw_ops/
fw_comps_mgr) не содержат транспортных проверок (grep `MST_DEV_I2C`/
`MDEVS_DEV_I2C`/`tp` по mlxfwops+flint — нуль функциональных попаданий,
журнал task-02): список и порядок секций определяются itoc образа +
burnParams (+ ответы FW при MCC — одинаково для любого транспорта).
Единственные реальные i2c-ветви (§9.1) не касаются состава записи.
Два нюанса:

1. **Косвенное семафорное отличие** (не ветвление по tp, а следствие
   `dinfo==NULL` на i2c): `mf_acquire_persistent_lock` (mflash.c:2120-2133)
   не ставит `unlock_blocked` (dm_is_livefish_mode≡0 на i2c) → семафор GW
   отпускается после каждой write-операции, тогда как PCI-livefish держит
   его до конца burn. На состав секций не влияет; возможный эффект на
   race с живым FW — гипотеза, **доказывается циклом 2**.
2. **Транспортонезависимый фолбэк MCC→DFA** сам меняет состав записи
   (компонентная запись против сырых секторов), но триггер — ответы FW
   (MCAM/secure_fw/MCC-ошибки), не i2c: на PCIe фолбэк тот же.

### 9.3 Live-зависимые пункты («доказывается циклом 2»)

- Отвечает ли FW на ICMD 0x9001 по i2c (живёт ли MCC-путь) — §7.6.
- Поведение flash-GW на livefish-карте по i2c (ICMD-open гейт пропущен,
   §7.5 п.1; GW в livefish может быть залочен HW).
- Достаточность busy-poll skip на реальных таймингах шины (§7.4).
- Фактический эффект семафорного отличия §9.2 п.1.
- Набор секций, фактически записываемых на живой карте при MCC vs DFA
  (косвенная проверка «одинаково ли для i2c и PCI»).

**Live-статусы (2026-11-21, цикл 2 T3, функциональная CX-5; журнал
`…-mtusb-i2c-hw-task-03.md`):**

- busy-poll skip (§7.4/O9) — **подтверждён (T6, FNP/livefish)**: RDID и
  полный дамп 16 MiB исполнены без пере-чтения CMD между Go и DATA-чтением;
  0 ошибок на 1 048 576 блоках (история: на функциональной карте T3 не
  проверяемо — семафор у живого FW).
- «Поведение flash-GW на livefish-карте» — **закрыто позитивом (T6,
  2026-11-22, FNP; журнал `…-mtusb-i2c-hw-task-06.md`)**: семафор при
  входе занят HW — ожидание «GW залочен HW» подтверждено (i2c bit31=1
  стабильно; PCI `q`/`rb` дают тот же `Can not obtain Flash semaphore`).
  Решение: force-release W CMD=0 (T15-прецедент «taking flash lock even
  though semaphore is set»; в тулинге — `--force-lock`) — освобождает
  персистентно обе стороны (после i2c-очистки PCI-rb 16 MiB прошёл,
  байт-в-байт == i2c-дампу, md5 7b96921b0fdfec100171cb426919cb9d).
  GW-активность (записи в DATA-окно) провоцирует re-assert семафора.
  Факт по функциональной карте (T3, сохраняет силу): семафор может
  удерживаться живым FW персистентно → GW-путь там не гарантирован.
- ICMD-версия поверх i2c (§7.5 п.2/O6) — **жива** (версия=1 @0x0,
  CX-5; cmd_ptr=0x2000); обмен (семафор/mailbox) не пробовался —
  вне write-политики таска. *(Цикл 3, T5: обмен подтверждён — полный
  `q` по ICMD через ch34x на functional CX-5, H1 SUCCESS; журнал
  `2026-11-22-mtusb-i2c-impl-task-05.md`.)*
- Эффект семафорного отличия §9.2 п.1 — наблюдалась удержка семафора
  самой FW (не клиентом; клиент lock не брал ни разу); race-поведение
  клиента не проверялось.

**Live-вердикт Q5/O8 (2026-11-22, цикл 3 T7; журнал
`2026-11-22-mtusb-i2c-impl-task-07.md`).** Парные burn одного образа
(T6-дамп 16 MiB, FNP-карта, legacy-набор `-ocr -apc --nofs
--ignore_dev_data -y`) — PCI-базлайн (1 м 58 с) против ch34x-i2c
(22 м 46 с, frames-трейс): состав операций идентичен — те же фазовые
маркеры построчно, тот же регистровый набор GW (RDID/READ/RDSR/WREN/PP/
SE + window-оппы), `-E-` 0/0, оба verify md5 == T6-дампу.
**Транспортных ветвлений на уровне операций нет — sole op-stream
branch; semaphore cadence differs per §9.2 п.1 (observed per-op on i2c
— 96364 lock/unlock-пары @0xf0420 в frames-трейсе; PCI unobservable,
no trace hook).** Различие только латентностное (транспортный множитель
≈11.5×); единственная кодовая транспорт-ветвь — латентностный пропуск
busy-poll §7.4 (состав команд не меняет: WIP-поллы идут штатным
RDSR-циклом).

## 10. Электрика/подключение (Q3: мануалы)

Ссылки секции: **PRM** = `refs/docs/ethernet-adapters-programming-manual.txt`
(«Mellanox Adapters Programmer's Reference Manual (PRM), Supporting
ConnectX-4 and ConnectX-4 Lx, Rev 0.40», PRM:1-5); **MFT-doc** =
`refs/docs/nvidia-firmware-tools-mft-documentation-v4-29-0.0.txt` (MFT
v4.29.0). Формат ссылки `PRM:NNN`/`MFT:NNN` — строка txt-файла; страницы —
по футерам pdf2text. Итог секции: мануалы дают **функциональную модель**
(назначение интерфейса, роли, slave-адрес, две шины, физическая модель
подключения MTUSB-1) и **не дают электрику** (уровни, pull-ups, частота,
pinout) — полный список пробелов §10.4, семантика «не найдено ≠
опровергнуто».

### 10.1 PRM §1.2.1.3 «I2C-Compatible» (стр. 28)

Дословно (PRM:1143-1149, §1.2.1.3; единственное содержательное место
мануала про I2C):

> «The I2C-compatible interface is designed to enable out-of-band access
> to the device, chassis management (IBML/SMBUS), and is used for HW debug.
> This interface is also designed to enable Mellanox debug tools to access
> the device, even in the event of other interfaces being down. The adapter
> device can be either a master or a slave on this interface (slave
> address is 0x48), and can support two different I2C-compatible
> interfaces for redundancy/fault tolerance.»

Разбор по фактам:

- **Назначение**: out-of-band доступ к девайсу, chassis-менеджмент
  (IBML/SMBUS), HW debug; доступ debug-инструментам «even in the event of
  other interfaces being down» — т.е. интерфейс задуман как канал
  восстановления (консистентно с FNP-сценарием mstflint, 850-howto).
- **Роли**: девайс «can be either a master or a slave»; в MTUSB-модели
  (§10.2) карта — slave, адаптер — master.
- **Slave-адрес 0x48** — совпадает с дефолтом mtcr (§1, `mtcr_ul_com.c:2806`)
  и livefish/non-secure-геном (§3). PRM адрес 0x47 (secure-gen, §3 п.5) не
  упоминает — мануал CX4/CX4Lx-эпохи, secure-поколений не знает; «не
  найдено ≠ опровергнуто».
- **Две шины**: «can support two different I2C-compatible interfaces for
  redundancy/fault tolerance» — назначение (редундантность/отказоустой-
  чивость) без деталей: как шины нумеруются/выбираются, какие выведены
  физически — мануал не говорит (§10.4). В mtcr-коде (§1–§3) понятия
  «вторая шина» нет вовсе — выбор шины, если он есть, лежит ниже
  i2c-dev-интерфейса (в `/dev/i2c-N` номер N и есть выбор шины/адаптера;
  для MTUSB-модели — выбор mux-маршрута, §10.2.3/§10.4).

Контекст §1.2 «Hardware Interfaces» (стр. 27-28, PRM:1075-1118): Figure 1
«System Interface» рисует I2C-Compatible наравне с Flash Interface, GPIO,
NC-SI, JTAG, PCIe, network ports (PRM:1078-1098); в списке интерфейсов
I2C-Compatible — в группе «Host Interfaces» рядом с PCIe (§1.2.1.1) и
NC-SI (§1.2.1.2) (PRM:1104-1108). GPIO-пункт списка отсылает детали
наружу: «See relevant Adapters Datasheets for details» (PRM:1114-1117) —
pinout-уровень в PRM систематически вынесен в datasheets (в refs/docs их
нет).

Полнота поиска (bounded, весь файл 17937 строк): паттерн
`i2c|smbus|ibml` (case-insensitive) — ровно 7 строк-хитов: TOC PRM:80,
Figure 1 PRM:1088, список PRM:1108, тело §1.2.1.3 PRM:1143-1149 (строки
:1143, :1145, :1146, :1149) — других I2C-/
SMBus-секций в мануале нет. Электрика-термины (`pull-up|open-drain|SDA|
SCL|kHz|voltage level|test point|pinout|bus speed`, case-insensitive) —
единственный хит «SCL» внутри слова «DISCLAIMED» (легал-бойлерплейт,
PRM:25), т.е. реальных упоминаний нуль. Охват PRM — только CX4/CX4Lx
(TOC/титул); для прочих поколений факты §1.2.1.3 этим источником не
подтверждены и не опровергнуты.

### 10.2 MFT-doc: MTUSB-1 как i2c-бус

Вердикт о классе документа (подтверждён фактом): MFT-doc — пользовательская
документация. (а) структура — «User Manual» (стр. 33, TOC MFT:33) — все
главы ниже, включая MTUSB-1; (б) глава MTUSB-1 сама декларирует объём:
«This chapter provides the user with hardware and software installation
instructions» (MFT:15951-15954, стр. 313); (в) проводных деталей (уровни/
pull-ups/частота/SDA-SCL-нейминг) файл не содержит — grep
`pull-up|open-drain|SDA|SCL|kHz|voltage|signal level` даёт хиты только в
cable-диагностике (напряжения питания кабелей: MFT:12234, MFT:15054-15096,
MFT:18686), не про I2C-шину. Ожидать от MFT-doc фрейминг-электрику нельзя
— она туда не входит by design.

#### 10.2.1 Роль и энумерация

- Роль в MFT: «MFT tools access NVIDIA devices via the PCI Express
  interface, via a USB to I2C adapter (P/N: MTUSB-1), or via vendor-specific
  MADs over the InfiniBand fabric (In-Band).» (MFT:1869-1871, стр. 35) —
  MTUSB-1 (part number) — один из трёх каналов доступа наравне с PCIe.
- mst-имя: «This name is assigned by running the command 'mst start' … for
  PCI and I2C access» (MFT:1885-1887, стр. 36); формат — «Via USB to I2C
  adapter: For example, mtusb-1.» (MFT:1936, стр. 37).
- Энумерация: `mst start` печатает «MTUSB-1 USB to I2C Bridge - Success»
  (MFT:2299-2304, стр. 44); `mst status` — «/dev/mst/mtusb-1 - USB to I2C
  adapter as I2C master» + «iSerial = 0x1683» (MFT:2339-2340, стр. 45);
  `mst status -v` выделяет секцию «I2C devices» c колонкой Serial
  (MFT:2358-2361). На Windows — `mtusb-1`, `mtusb-2`… + iSerial
  (MFT:2557-2559, MFT:2577-2578, стр. 48-49): несколько адаптеров MTUSB
  различаются по USB iSerial. Переименование: правило mst.conf `RENAME $TYPE $NEW_NAME
  $ID`, тип `MTUSB`, `$ID` = iSerial, «always mtusb-1 will be concatenated
  to the new name» (MFT:2284-2291, стр. 44).
- Каноническое имя из главы MTUSB-1: «If MTUSB-1 has been correctly
  installed, "mst status" should include the following device …: On Linux:
  /dev/mst41:00.0/mtusb-1 / On Windows: mtusb-1» (MFT:16037-16042,
  стр. 316) — linux-путь в этой строке выглядит как опечатка документа
  (везде остальное — `/dev/mst/mtusb-1`, напр. MFT:2339); констатация расхождения
  внутри самого MFT-doc, без выбора — для спеки использовать общепринятое
  `/dev/mst/mtusb-1` (как в примерах инструментов, §10.2.4).
- Контраст с код-каноном §1 («Энумерации нет» в mtcr для `/dev/i2c-N`):
  здесь энумерацию делает **mst-слой**, а не mtcr-скан PCI-шины — мост
  USB→I2C презентуется как mst-девайс `/dev/mst/mtusb-1` (внутри —
  usb-бэкенд mtcr, вне пина mstflint-аудита task-01/02; это MFT-сторонняя
  модель, не mtcr_ul i2c-бэкенд §1).

#### 10.2.2 Физическая модель подключения (глава «MTUSB-1 USB to I2C Adapter», стр. 313-318)

- Определение: «The MTUSB-1 is a USB to I2C bus adapter.» (MFT:15951-15952).
- Комплект (MFT:15966-15974, стр. 314): устройство MTUSB-1; USB-кабель
  USB_A→USB_B (1.8 м); **I2C-кабель 9-pin male-to-male (1.5 м)**;
  **2× конвертер-кабеля «9-pin female to 3-pin (small/large)» (0.3 м)**.
- Подключение (MFT:15998-16006, стр. 315): USB-конец → ПК; I2C-кабель →
  «the system/board you wish to control via the I2C interface»; «If the
  system/board uses a 3-pin connector instead of a 9-pin connector, connect
  the appropriate converter cable as an extension to the I2C cable on the
  9-pin end, then connect its 3-pin end to the system/board.» — т.е.
  целевая сторона (плата) имеет либо 9-pin, либо 3-pin разъём; 3-пин —
  согласуется с pin-фактом владельца (GND+SDA+SCL = 3 сигнала, §10.3), но
  назначение контактов 3-pin (и 9-pin) разъёмов MFT-doc не раскрывает.
- USB: «USB Standard 1.1 or later» (MFT:15984-15986, стр. 315). Платформы:
  «MTUSB-1 is supported in Linux and Windows only» (MFT:15992). Софт:
  обязателен MFT-пакет (MFT:16012-16013); на Windows — драйвер с
  «http://www.diolan.com» (MFT:16015-16017) — MTUSB-1 основан на
  Diolan-адаптере (факт из ссылки на драйвер, глубже мануал не идёт).
  Зависимость окружения: lsusb «Required for the mtusb device usage»
  (MFT:583, сноска 4 MFT:609, стр. 10).
- Никаких электрических параметров шины (уровни, pull-ups, частота,
  длина/ограничения шины сверх длин кабелей) глава не содержит —
  installation-instructions-класс (см. вердикт выше).

#### 10.2.3 Кабельная модель (MTUSB Cable Board, стр. 298)

Дословно (MFT:15224-15227): «The mlxcables tool supports reading cable data
directly via i2c when the cable is connected to a dedicated board. The
board is connected to the host with an MTUSB adapter.» После `mst cable
add` в `mst status` появляется кабельный pseudo-девайс `mtusb-1_cable`
(MFT:15233-15243); чтение — `mlxcables -d mtusb-1_cable` (EEPROM-дамп
кабеля, MFT:15252-15271) и побайтово `mlxcables -d mtusb-1_cable -r -p 0
-o 165 -l 3` (MFT:15280-15287). Cross-ref: cable-id (0x03/0x0d/0x11/0x19)
в supported-таблице mtcr (§5 прим. б) — та же модель кабельных
pseudo-девайсов; «compatible board»-требование подтверждено и release-note
(MFT:18616-18618, «support to access the cable via the MTUSB, when the
cable is connected to a compatible board»).

#### 10.2.4 Операции над mtusb-девайсом и ограничения

- flint: burn/query — основной кейс; erase-пример `flint -d /dev/mst/mtusb-1
  e 0x1000` (MFT:7163, стр. 141). **Ограничение скорости** (дословно,
  «flint/mlxburn Limitations», стр. 144, MFT:7328-7334): «When running
  flint/mlxburn via an MTUSB-1 device, a burn/query command may take up to
  45 minutes to complete. … To accelerate the burn process add the flag
  -no_flash_verify to the command line which skips the flash verification
  step. This flag, however, does not verify if the image is burnt
  correctly.» Смежный кейс (стр. 145, MFT:7340-7344): при сбое flash-recovery
  burn из-за PCIe spread spectrum — «To burn the device, use the MTUSB-1
  connection» (MTUSB-1 как канал обхода PCIe-проблем).
- flint `-qq`: «Run a quick query … shorten execution time when running
  over slow interfaces (e.g., I2C, MTUSB-1). Commands affected: query»
  (MFT:5088-5096, стр. 99-100) — документированное признание I2C/MTUSB
  медленным интерфейсом.
- mlxi2c (стр. 200-201, MFT:10037-10084): `-d <device>` default
  «/dev/mst/mtusb-1»; `-s, --i2c-secondary <address>` — «Change the I2C
  secondary address» (интерфейс к смене sec-addr, код-канал §3);
  команды `p <i2c_component>` (route) и `scan` («Scan the i2c slave
  addresses», пример `mlxi2c -d /dev/mst/mtusb-1 scan`).
- i2c-утилита (стр. 201-203, MFT:10089-10191): low-level r/w на «any NVIDIA
  switch platform» (формулировка главы; в общей tools-таблице — шире:
  «Generates an i2c transaction using an mtusb usb to i2c adapter or using
  the device internal i2c compatible master», MFT:481-483, стр. 8 — второй
  вариант = внутренний i2c-мастер девайса, альтернатива MTUSB);
  синтаксис `i2c [OPTIONS] <device> <cmd> <i2c_addr> <addr> [<data>]`;
  `-a <addr_width>` 0/1/2/4 байта, **default 1**; `-d <data_width>` 1/2/4;
  `-x <len>` hex-блок. Пример: `i2c -a 2 -d 2 /dev/mst/mtusb-1 r 0x56
  0x00`. Cross-ref §2.6: адресные ширины совпадают с вариантами энкодера
  prepare_i2c_buf (MST_GAMLA 2Б / MST_DIMM 1Б / TAVOR 4Б); mstflint-флоу
  NIC всегда 4 Б (§1) — утилита generic, дефолт мягче.
- Прочие инструменты: itrace по I2C — `-d` = «an I2C device (such as
  mtusb-1)» + «If the cr-space device … is one of the I2C devices, -nomap
  is switched on» (MFT:9859-9879, стр. 196-197); удалённый доступ — mst
  server/remote, mtusb-1 виден клиенту как `/dev/mst/mft:23108,@dev@mst@
  mtusb-1` (MFT:16110-16122, MFT:16222, стр. 317-318); mlxlink на adapter
  card через MTUSB — порт 2 адресуется `--gvmi_address<0xAddress>`
  (MFT:12390-12397, стр. 245); mlxconfig apply token via MTUSB (release
  note Rev. 4.20.0, MFT:17729-17731).
- Известные ограничения-история (known issues, MFT:20101-20106): «Burning
  tools cannot burn over mtusb interface, the tool will exit with the
  following error "mf object is NULL"» — bug 2248709, discovered 4.15.0,
  fixed 4.16.0 (т.е. burn-over-MTUSB-инфраструктура была сломана между
  4.15 и 4.16; на v4.29 считается рабочей).

### 10.3 Сверка pin-факта владельца (GND / SDA-«SCA» / SCL)

Факт владельца (2026-11-19, вход задачи): на картах есть пины GND (земля),
SDA/«SCA» (данные), SCL (клок). Сверка с источниками:

| пин (владелец) | PRM §1.2.1.3 | MFT-doc | вердикт |
|---|---|---|---|
| GND | не упоминается | не упоминается | не противоречит; 3-пин модель MFT:16003-16006 оставляет место (GND+2 сигнала) |
| SDA / «SCA» (данные) | сигналы не именуются | сигналы не именуются | назначение «данные» консистентно роли шины (CR-доступ §2); нейминг «SCA» мануалами не подтверждён и не опровергнут (стандарт I2C — SDA) → live-проверка маркировки |
| SCL (клок) | сигналы не именуются | сигналы не именуются | консистентно (I2C-шина подразумевает клок); имя мануалом не зафиксировано |
| две шины | «two different I2C-compatible interfaces for redundancy/fault tolerance» (PRM:1148-1149) | — | назначение известно; какая шина выведена на пины/разъём карты — мануал не говорит → live |
| физическое расположение | молчит (pinout вынесен в datasheets, PRM:1114-1117) | молчит (только кабели/разъёмы адаптера, MFT:15966-16006) | где пины/test points на типовой карте — мануалами не покрывается → live |

Вердикт: **расхождений мануал↔владелец нет** — pin-факт согласуется с
I2C-Compatible-интерфейсом PRM и 3-пин разъёмом MFT-модели; всё, что
владелец знает сверх мануалов (имена пинов на плате, «SCA»-вариант
маркировки, расположение), мануалами не покрывается и не оспаривается —
уходит в live-список §10.4. Разрешение live-вопросов — цикл 2, не эта
секция.

### 10.4 «Чего мануалы не говорят» — live-уточнения цикла 2

Все пункты — «не найдено ≠ опровергнуто»: отсутствуют в обоих источниках
(поиски §10.1/§10.2 воспроизводимы), но мануалы их и не отрицают.

1. **Уровни сигналов** (напряжение лог.0/1, Vdd шины) — нуль упоминаний.
2. **Pull-ups**: наличие, номиналы, расположение (на карте / на MTUSB-1 /
   внешние обязательны) — нуль упоминаний; для открытого стока I2C критично
   для самодельного подключения.
3. **Частота шины** (standard 100 кГц / fast 400 кГц / fast-plus),
   тайминги, ограничения длины — нуль упоминаний (максимальная длина known:
   кабели адаптера 1.5+0.3 м, MFT:15970-15974).
4. **Две шины**: какие физически выведены (обе? одна? куда), как
   выбираются, поведение фейловера — PRM даёт только формулировку
   redundancy (PRM:1148-1149).
5. **Физический доступ на типовой карте**: где пины/test points/разъём,
   маркировка (в т.ч. «SCA» vs SDA на шелкографии), 3-pin или 9-pin
   посадка — мануалы молчат (PRM отсылает к datasheets, которых нет в
   refs).
6. **Pinout разъёмов MTUSB-1**: назначение контактов 9-pin и 3-pin
   (small/large) конвертеров — в комплект-листе имена есть, распиновки нет.
7. **Электрика/ID Diolan-ядра**: MFT-doc ссылается на драйвер diolan.com
   (MFT:16015-16017) — VID/PID, протокол USB-моста вне обоих мануалов.

### 10.5 Требования электрики/подключения для Task 6 (перенос в спеку)

Сформулировано для переноса в транспортную спеку без перечитывания
мануалов; live-зависимые пункты помечены [live: §10.4-№].

- Физический доступ: 3-проводное подключение к карте — GND, SDA (данные),
  SCL (клок) [live-нейминг/расположение: §10.4-5]; посадка — 3-pin или
  9-pin разъём [live: какой на целевой карте; 9↔3-переходник из комплекта
  MTUSB-1, MFT:15974].
- Роли: внешний мастер (I2C master) ↔ карта slave; slave-адрес **0x48**
  (PRM:1148; mtcr-дефолт §1), secure-gen функциональный **0x47** (код-канон
  §3; PRM не знает). Смена secondary-адреса — клиентская опция
  (mlxi2c `--i2c-secondary`, §10.2.4; mtcr §3).
- Шины: документированы две шины redundancy/fault-tolerance (PRM:1148-1149);
  выбор/наличие на конкретной карте [live: §10.4-4].
- Электрика: уровни, pull-ups, частота — не задокументированы; для спеки —
  либо datasheets (вне refs), либо [live-замер §10.4-1..3]; до уточнения
  консервативный дефолт I2C (открытый сток + внешние pull-ups, slowest
  standard-mode) — гипотеза цикла 2, не мануальный факт.
- Модель шины MTUSB: USB→I2C мост, презентуется mst-слоем как
  `/dev/mst/mtusb-1` («USB to I2C adapter as I2C master», MFT:2339);
  различение нескольких адаптеров — USB iSerial (MFT:2577-2578);
  кабельная модель — отдельные pseudo-девайсы `mtusb-N_cable` (§10.2.3).
- Операционные параметры: burn/query через MTUSB-1 — таймауты до **45
  минут** (MFT:7329-7330); ускорение burn — `-no_flash_verify` (пропуск
  flash-verification, образ не проверяется, MFT:7332-7334); ускорение
  query — `-qq` (пропуск полных integrity-проверок, MFT:5088-5096);
  I2C/MTUSB документирован как «slow interface» — таймауты спеки считать
  от этих величин, не от PCIe-таймингов.
- Утилитарная поддержка (для приёмочных тестов спеки): flint
  burn/query/erase, mlxburn, mlxi2c scan/secondary, i2c r/w (ширины адреса
  0/1/2/4, дефолт 1), itrace (--nomap авто), удалённо — mst server/remote
  (§10.2.4).

## 11. Свитчи (Q4)

Контекст владельца (вход задачи): доступ к свитчу — двумя путями — через
**ib_umad** (inband; нужен mst/umad-стек) и через **I2C**. Мандат
2026-11-19: мануалы свитчей специально НЕ искать — только pinned refs.
Итог: switch-over-i2c данные в pinned refs **есть** (код-таблицы +
MFT-doc); отдельного свитч-протокола поверх §2 они не фиксируют.

### 11.1 Кодовые улики (свитчи в i2c-путях mstflint)

- **Приём свитч-идов i2c-open'ом**: свитч-иды входят в
  `supported_device_ids` (SwitchIB 0x247, Spectrum 0x249, SwitchIB2 0x24b,
  Spectrum2–6, Quantum 0x24d, QTM2/3, NVLink6, CX8/9-PurePCIeSwitch;
  `mtcr_ul/mtcr_ul_com.c:2836-2884`) и в secured (QTM2 0x257, QTM3 0x25b,
  NVLink6-Switch 0x278, CX8/9-PPS 0x222/0x228 → 0x47, `:2830-2832`;
  значения — `dev_mgt/tools_dev_types.h:141-184`). Т.е. probe свитча по
  i2c принимается открытием §1, secure-gen свитч уходит на 0x47 той же
  механикой §3 п.5, что NIC (журнал task-01 «Материал для Task 4»).
  Транспортных ветвлений «свитч vs NIC» в i2c-коде нет: функциональные
  `MST_DEV_I2C`/`MDEVS_DEV_I2C`-ветви всего три (§9.1 — busy-skip,
  ICMD-init, `--i2c_secondary`), ни одна не девайс-специфична (аудит
  task-01/02).
- **mflash**: свитчи — полноправные девайсы gen-таблиц §7.1; legacy-имена
  этого пути — свитчевое наследие: `is4_flash_lock` («InfiniScale 4 (IS4)
  functions», mflash.c:1630-1638) и `sx_flash_init_direct_access` (SwitchX,
  mflash.c:2312-2316) — тот же GW 0xf0400, транспорт в диспетче не
  участвует. `is_icmdif_supported`: SwitchIB/SwitchIB2/Spectrum/Quantum → 1
  (mflash_dev_capability.c:119-166) — ICMD-путь §7.5 доступен свитчам;
  их CR-адреса — таблица §7.5 п.2 (строка «свитчи SW-IB/QTM»).
- **Семантические свитч-ветви** (не транспортные): MGIR `dev_sc` вместо
  `dev` для свитчей/ретаймеров (fw_comps_mgr.cpp:2044-2053), virtual
  local-port 0 → 1 для multi-ASIC (fsctrl_ops.cpp:483-497) — поверх
  рег-доступа (на i2c — ICMD §7.5), на проводе §2 не сказываются.
- **ib_umad-путь** (первый путь контекста владельца; для полноты, вне
  i2c-канона): виртуальные имена `lid-`/`iblid-`/`ibdr-` → `MST_IB`
  (`mtcr_ul_com.c:2438-2441`, парсер `:3040-3045`); CR-доступ — SMP MAD
  `IB_SMP_ATTR_CR_ACCESS` через динамически загружаемую libibmad
  (`LIB_IBMAD "libibmad"` mtcr_ib_ofed.c:78; send `:450`); единственная
  tp-ветка MCC-слоя — inband `tp == MST_IB` (fw_comps_mgr.cpp:1062, §7.6);
  `msw_reset` — только для MST_IB (mtcr_ul.c:64-79). Фрейминг MAD ≠ §2;
  свитч-специфика inband-пути в этом каноне не разбирается.

### 11.2 MFT-doc: документированная практика switch-over-i2c

Материал всплыл в task-03 (журнал, scope guard); глава MTUSB-1 — pinned
ref (`refs/docs/nvidia-firmware-tools-mft-documentation-v4-29-0.0.txt`),
не целевой поиск мануалов. Пины верифицированы в task-04.

- **«Switch Reprogramming through I2C Port»** (MFT:16047-16105,
  стр. 316-317): «In order to reprogram the switch through the I2C
  adapter» — процедуры по системам: (а) MSX1710/MSX67XX — открыть bus:
  `i2c -a 1 -d 1 /dev/mst/mtusb-1 w 0x60 0x20 0x10` и
  `i2c -a 1 -d 1 /dev/mst/mtusb-1 w 0x62 0x00 0x01`; (б) MSX6025/6036 —
  открыть bus `i2c -d /dev/mst/mtusb-1 w 0x22 0x1a 0xfb`, route на свитч
  `i2c -d /dev/mst/mtusb-1 w 0x70 0x0 0x1`; далее в обоих случаях
  `flint -d /dev/mst/mtusb-1 -i ./fw-SX.bin b` и power cycle системы
  (unplug/replug шнура питания — «to load the new firmware»). Модель:
  свитч-система = i2c-шина с **mux'ами** (адреса 0x60/0x62/0x22/0x70 —
  платформенные, в mtcr-коде отсутствуют); mux-команды шлются утилитой
  `i2c` ДО flint, после роутинга flint видит обычный mst-девайс
  `mtusb-1` — burn-флоу §8.3/§8.4 без свитч-специфики.
- **SwitchX через mtusb-1**: blank-flash burn `flint -d /dev/mst/mtusb-1
  -i /tmp/fw-sx.bin -nofs -guids … -macs … b` (MT58100 SwitchX,
  MFT:5469-5481, стр. 107); route-вариант `mlxi2c -d /dev/mst/mtusb-1
  p SX` («Set the I2C network to access the SwitchX switch») + `mlxburn
  -d /dev/mst/mtusb-1 … MSX6025F_A1.ini` (MFT:8235-8249, стр. 163);
  tools-таблица mlxi2c: «Routes the i2c bus of an externally managed
  InfiniscaleIV/SwitchX system to connect to the switch silicon» /
  «Scans the i2c bus» (MFT:485-489, стр. 8).
- **Switch-IB unmanaged**: «For unmanaged switches, connect an MTUSB
  adapter (see MTUSB-1 USB to I2C Adapter) to the device and use the
  appropriate mst device (/dev/mst/mtusb…)» (MFT:17015-17017, стр. 336;
  :17014 — футер стр. 335, :17018+ — пустые)
  — MTUSB документирован как канал для несетевых (unmanaged) свитчей;
  managed-варианты идут через хост.
- **Утилиты `i2c`/`mlxi2c` — MFT-side**: в pinned mstflint-дереве их нет
  (small_utils: mcra/mread/mwrite/mget_temp и пр. — без i2c-утилит);
  их функциональность в mstflint-коде — `mset_i2c_secondary` §3
  (runtime-смена) и SDK-обёртка `mft_sdk/mft_sdk_i2c_access.cpp`
  (журнал task-02, искл. п.9).

### 11.3 Вердикт

**Switch-over-i2c данные по pinned refs есть; отдельного протокола нет.**
Код: свитчи принимаются i2c-транспортом как обычные девайсы (таблицы §3/§5,
единый фрейминг §2, единая slave-механика 0x48→0x47; mflash/ICMD
gen-таблицы §7 включают свитчи). MFT-doc: switch reprogramming через
MTUSB-1 документирован (MFT:16047+) — отличия от NIC-флоу только
платформенные: mux-роутинг до flint (утилитой i2c/mlxi2c, адреса
системные) и обязательный power cycle после burn. Не зафиксировано
(«не найдено ≠ опровергнуто»; Q4 для арки неблокирующий): slave-адрес
свитча за mux'ом (дефолт-модель — тот же 0x48, §1; подтверждений обратного
нет), wire-поведение livefish-свитчей, применимость 0x47-механики к
старым SX/IS4-генам (в secured-таблице их нет — только новые, §3) —
уточнять при появлении свитч-железа (live-цикл 2), не задерживая арку.

Правило: свитч-материал, всплывающий по смежным задачам (live-цикл,
mst-слой, ib_umad-детали, платформенные mux-карты), — дополнять в эту
секцию без задержки арки.

## 12. Эмпирическая валидация (офлайн-стаб, task-05)

Метод: сборка mstflint с включённым i2c-бэкендом (`--enable-i2c` →
`-DENABLE_MST_DEV_I2C`; сиблинг `mstflint-container`, ветка
`mtusb-i2c-re`, upstream `1b8ac4b5` + патч-серия v4.37.0-1.4) против
LD_PRELOAD-стаба `scripts/i2c-capture-shim.c` сиблинга: перехват
`open/open64/openat` путей `/dev/i2c*` (реального узла нет — кернел-модуль
`i2c-stub` отсутствует в ядре toolbx, `modprobe` → not found), `ioctl`
(декодированный дамп каждого `i2c_msg`: addr/flags/len/байты; read-буферы
заполняются повторяемым паттерном), `close`, и `geteuid`→0 (см. п.12.3-4).
Артефакты и SHA256 — `build/manifest-task5-i2c.txt` сиблинга (untracked,
прецедент 24211aec): AppImage
`7d9f470c1d8c21375d6645b68a86e8524089a05743c6b47ae3fea260562b24f6`,
внутренний `mstflint`
`4c92b063d66613303afe1a8dfedfc4387a66cd8f1a5f01e0e6548272c35eeccb`;
включённость i2c проверена `nm` (14 i2c-символов на бинарь, включая
`mtcr_i2c_mread4/mwrite4`, `change_i2c_secondary_address`) и build-гейтом
`/dev/i2c`-literal. Логи сценариев s1–s10: `build/task5-captures/` сиблинга
(SHA — там же). Паттерны: default `00000209` (CX4 — supported, non-secured
→ остаёмся на 0x48), `00000218` (CX7 — secured → §3 п.5), `0000beef`
(unsupported), per-slave override для mismatch-ретраев. Транскрипты ниже
байт-точные из логов (нумерация `[N]` — счётчик событий стаба; `w:`/`r:` —
write/read-фаза, len в байтах).

### 12.1 Подтверждённое (эмпирика против канона)

| пункт | эмпирическое подтверждение | сценарий |
|---|---|---|
| §2.1 фрейминг mread4 | combined 2-msg: W `BE32(addr)` ‖ R 4Б; байты `00 0f 00 14` = BE32(0xf0014) | s1, s2, все |
| §2.2 фрейминг mwrite4 | 1-msg len=8: `00 0f 00 14 12 34 56 78` = BE32(addr)‖BE32(val) | s3 |
| §2.3 блочное чтение | 64Б = ОДИН ioctl-чанк (msg[0] W `BE32(0xf0014)`, msg[1] R len=64); внутри чанка адрес не повторяется — автоинкремент slave подразумевается | s2 (`mstmcra 0xf0014,64`) |
| §2 «ретраев в mtcr-слое нет» | ни одной повторной транзакции кроме §3-цикла; errno-вариант стаба сразу валит вызов | s1–s10 |
| §2.5 probe = mread4@0xf0014 | первая транзакция каждого mopen | s1–s8, s10 |
| §3 п.2/4 (0x48 остаётся) | probe@0x48 → supported+non-secured → одна проба, всё дальше @0x48 | s1–s5 |
| §3 п.3 (fail-ветка) | probe@0x48 → unsupported → probe@0x47 → не secured → отказ open (ровно 2 пробы) | s7 |
| §3 п.5 (0x48→0x47) | probe@0x48 (secured id) → probe@0x47 (id совпал) → все дальнейшие транзакции @0x47; **никаких write-транзакций при смене адреса** («на проводе смена не существует») | s6 |
| §3 п.5 retry-цикл | mismatch id: 1 probe@0x48 + 1 предварительный probe@0x47 + **ровно 100** retry-probe@0x47 (10 мс кадence) → отказ; всего 103 события | s8 |
| §3 п.1 force | `--i2c_secondary 0x49`: после open НИ ОДНОЙ пробы — сразу dev-id@0x49 | s9 |
| §7.2 командное слово RDID | GW CMD write = `c0 9f 02 15` (0xC09F0215 — байт-точно формула §7.2/§8.1) | s5, s9, s10 |
| §7.3 GW-цикл (legacy/CX4) | poll CMD@0xf0400 (бит31=0 → взял) → RMW@0xf0420 (disable) → W CMD (Go) → R DATA@0xf0410 → RMW@0xf0420 (restore) → W CMD=0 (unlock) | s5, s9, s10 |
| §7.4 busy-poll skip | между CMD-write (Go) и DATA-read нет ни одного пере-чтения CMD | s5, s9, s10 |
| §7.5 п.2 таблица адресов | ICMD-версионная проба читает @cmd_ptr/hcr: CX4 → `00 00 00 00` (0x0), SwitchIB → `00 08 00 00` (0x80000) — ровно адреса таблицы §7.5 п.2 | s4/s5 vs s10 |
| §7.5 version-гейт первый | версия (биты 24..31 паттерна = 0 ≠ 1) → ME_ICMD_UNSUPPORTED_ICMD_VERSION → **ни семафор, ни mailbox не читаются никогда** | s4, s5 |
| §7.6/§8.1 MCC-first + фолбэк | q без флагов: MCC (FwCompsMgr, отдельный mfile) падает на ICMD-версии → фолбэк в DFA (третий mfile) — фолбэк существует, как предсказано §7.6 | s4 |
| §8.3 п.0 cache-rep guard | guard читает @0xf0408/@0xf040c (пара GEN_5_LEGACY); nonzero → уход в FW-путь (icmd_init → версия → отказ). `-ocr`: на проводе `W BE32(0xf0014)‖BE32(0)` — reset-write HW_DEV_ID §8.3 п.0 байт-точно | s4 vs s5/s9 |
| §8.6 границы | см. п.12.5 | s4, s5 |

### 12.2 Транскрипты (байт-точно из логов)

**s1 — open/first-contact + CR-read** (`mstmread /dev/i2c-0 0xf0014`,
CX4-паттерн; вывод тула `Read 0x000f0014:0x00000209`):

```
[00001] open64 "/dev/i2c-0" flags=0x101002 -> fd=3 (stub)
[00002] I2C_RDWR fd=3 nmsgs=2                      ← probe §2.5 (смена sec-addr §3)
    msg[0] addr=0x48 flags=0x0000 len=4 w: 00 0f 00 14
    msg[1] addr=0x48 flags=0x0001 len=4 r: 00 00 02 09
[00003] I2C_RDWR fd=3 nmsgs=2                      ← сам mread4 §2.1
    msg[0] addr=0x48 flags=0x0000 len=4 w: 00 0f 00 14
    msg[1] addr=0x48 flags=0x0001 len=4 r: 00 00 02 09
```

**s3 — mwrite4** (`mstmcra /dev/i2c-0 0xf0014 0x12345678`): probe (как
выше) + `I2C_RDWR nmsgs=1 / msg[0] addr=0x48 flags=0x0000 len=8 w:
00 0f 00 14 12 34 56 78`.

**s2 — блочное чтение 64Б** (`mstmcra /dev/i2c-0 0xf0014,64`): probe + один
чанк: `msg[0] … w: 00 0f 00 14 / msg[1] addr=0x48 flags=0x0001 len=64 r:`
`00 00 02 09` ×16 (дворды BE — вывод тула 0x00000209 на каждый адрес).

**s6 — secured CX7, смена 0x48→0x47** (`mstmread`, паттерн 00000218;
вывод `Read 0x000f0014:0x00000218`):

```
[00002] … msg[0] addr=0x48 … w: 00 0f 00 14 / msg[1] … r: 00 00 02 18   ← probe@0x48: secured
[00003] … msg[0] addr=0x47 … w: 00 0f 00 14 / msg[1] … r: 00 00 02 18   ← probe@0x47: id совпал
[00004] … msg[0] addr=0x47 … w: 00 0f 00 14 / msg[1] … r: 00 00 02 18   ← чтение уже @0x47
```

**s7 — unsupported id** (паттерн 0000beef): probe@0x48 (`r: 00 00 be ef`)
→ probe@0x47 → отказ open; больше ни одной транзакции.

**s8 — mismatch-ретраи §3 п.5** (0x218@0x48, 0x209@0x47): `[00002]` @0x48
→ `[00003]` @0x47 (предварительный) → `[00004]–[00103]` — 100 probe@0x47
→ отказ; счётчик событий стаба 103 = 1 open + 102 I2C_RDWR.

**s9 — GW-цикл RDID при force-secondary 0x49** (`mstflint --i2c_secondary
0x49 -ocr -d /dev/i2c-0 q`; перед [00010] — open без проб, dev-id@0x49,
толерантная ICMD-проба (п.12.3-5), чтение 0xf0014; итог тула:
`-E- SPI flash #0 (vendor: 0, memory type: 0, es: 0) is not supported`):

```
[00010] I2C_RDWR fd=5 nmsgs=2                      ← dm_get_device_id (guard-ветка -ocr)
    msg[0] addr=0x49 flags=0x0000 len=4 w: 00 0f 00 14
    msg[1] addr=0x49 flags=0x0001 len=4 r: 00 00 02 09
[00011] I2C_RDWR fd=5 nmsgs=1                      ← §8.3 п.0: reset HW_DEV_ID (-ocr)
    msg[0] addr=0x49 flags=0x0000 len=8 w: 00 0f 00 14 00 00 00 00
[00012] I2C_RDWR fd=5 nmsgs=2                      ← GW-семафор: poll CMD@0xf0400, бит31=0 → взял
    msg[0] addr=0x49 flags=0x0000 len=4 w: 00 0f 04 00
    msg[1] addr=0x49 flags=0x0001 len=4 r: 00 00 02 09
[00013] I2C_RDWR fd=5 nmsgs=2                      ← cache-rep disable: R@0xf0420
    msg[0] addr=0x49 flags=0x0000 len=4 w: 00 0f 04 20
    msg[1] addr=0x49 flags=0x0001 len=4 r: 00 00 02 09
[00014] I2C_RDWR fd=5 nmsgs=1                      ← W@0xf0420 = 0x209&~1 (бит0=0)
    msg[0] addr=0x49 flags=0x0000 len=8 w: 00 0f 04 20 00 00 02 08
[00015] I2C_RDWR fd=5 nmsgs=1                      ← Go: CMD@0xf0400 = 0xC09F0215 (RDID, §7.2)
    msg[0] addr=0x49 flags=0x0000 len=8 w: 00 0f 04 00 c0 9f 02 15
[00016] I2C_RDWR fd=5 nmsgs=2                      ← DATA@0xf0410, 4Б jedec (без пере-чтения CMD — §7.4)
    msg[0] addr=0x49 flags=0x0000 len=4 w: 00 0f 04 10
    msg[1] addr=0x49 flags=0x0001 len=4 r: 00 00 02 09
[00017] I2C_RDWR fd=5 nmsgs=2                      ← cache-rep restore: R@0xf0420
    msg[0] addr=0x49 flags=0x0000 len=4 w: 00 0f 04 20
    msg[1] addr=0x49 flags=0x0001 len=4 r: 00 00 02 09
[00018] I2C_RDWR fd=5 nmsgs=1                      ← W@0xf0420 = |1 (restore 0x209)
    msg[0] addr=0x49 flags=0x0000 len=8 w: 00 0f 04 20 00 00 02 09
[00019] I2C_RDWR fd=5 nmsgs=1                      ← unlock: CMD@0xf0400 = 0 (§7.3 п.6)
    msg[0] addr=0x49 flags=0x0000 len=8 w: 00 0f 04 00 00 00 00 00
```

jedec-ответ `00 00 02 09` → vendor 0 → «flash type not supported» —
стаб-граница (§8.6). Никаких WREN/RDSR/RES-попыток: идентификация
останавливается на первом RDID.

### 12.3 Расхождения и уточнения (эмпирика → канон)

| # | пункт | было в каноне | наблюдение | разрешение по коду |
|---|---|---|---|---|
| 1 | §7.3 п.1/п.6, §7.1 (lock) | «lock = poll бита31 CMD + unlock-запись 0; …+ disable/restore cache-replacement» — адрес disable/restore не назван (в §7.1 перечислена только guard-пара 0xf0408/0xf040c) | lock-цикл на проводе содержит RMW-пару по адресу **0xf0420** (R → W с бит0=0; restore — R → W с бит0=1) | `connectib_flash_lock` (mflash.c:1904-1925) = `is4_flash_lock` (poll@CMD) + `disable_cache_replacement` (RMW `mfl->cache_repacement_en_addr`) [+restore при unlock]; `cache_repacement_en_addr = HCR_CACHE_REPLACEMNT_EN_ADDR = 0xf0420` (mf_open_fw mflash.c:3354; mflash_pack_layer.h:329). Т.е. **два разных cache-rep-регистра**: guard-пара 0xf0408/0xf040c (чтения при инициализации) и lock-time enable 0xf0420. В refs и build идентично — омиссия канона, не версионное расхождение |
| 2 | §7.3 (exec_cmd_get) | последовательность «lock → mwrite4(ADDR) → mwrite4(CMD) → mread4_block(DATA) → unlock» | RDID-обмен идёт **без ADDR-write** | RDID — безадресная SPI-команда: addr-phase-бит в 0xC09F0215 не ставится, `cntx_spi_get_type` не пишет ADDR (шаг ADDR выполняется только для адресных команд — как §7.3 и оговаривает для блоков-продолжений) |
| 3 | §8.1 п.3/§8.6 (граница q/DFA) | «стаб без FW увидит шаги 1–3 до … jedec-чтения (DFA)» — порядок стоп-точек не фиксирован | без флагов DFA-init умирает **раньше GW**: cache-rep guard (0xf0408/0xf040c ≠ 0) → `needs_cache_replacement` → `icmd_init` → version-отказ (`MFE_ICMD_NOT_SUPPORTED`); до семафора GW/jedec дело не доходит. С `-ocr` — доходит до GW+RDID (s5/s9) | `flash_init_with_cache_guard` (mflash.c:2574-2606): guard → FW-путь (ATBM_ICMD → icmd_init) либо direct; §8.6-список «остановится на cache-rep-регистрах» эмпирически уточнён порядком: cache-rep guard **раньше** GW-семафора/jedec |
| 4 | §1 (активация) | не отмечено | **euid-гейт**: непривилегированный mopen умирает с EACCES до любого open устройства | `mopen_ul` (build mtcr_ul_com.c:4032-4036 = refs :4032, идентично): `if (geteuid() != 0) {errno = EACCES; return NULL;}` — для Task 6: i2c-тулы требуют root (консистентно правам /dev/i2c-N) |
| 5 | §7/§8 (DFA-init) | ICMD-инициализация описана только в MCC/рег-access-путях | DFA-open (mf_open_fw) сам делает **толерантную** ICMD-пробу: пачка read_device_id@0xf0014 + одно версионное чтение @hcr (CX4 0x0; SWIB 0x80000 — подтверждение таблицы §7.5 п.2); отказ не фатален, поток идёт дальше | `get_dev_info` (mflash.c:3066-3076) → `mf_get_secure_host` (mflash.c:5092) → `reg_access_secure_host` → `maccess_reg` → ICMD §7.5 п.6; сбой игнорируется (`if (!mf_get_secure_host(...) && mode)`) |
| 6 | §2.4 (mwrite4_block) | 32Б-чанки — код-факт | эмпирически НЕ подтверждена: ни одна утила не водит block-write без FW (`mstmcra` блок-write не поддерживает — «Writing blocks is not supported yet», mcra.c; `mstmwrite` — только dword; ICMD-mailbox/burn — FW-гейты) | остаётся код-верифицированной (§2.4); live-проверка — цикл 2 (или транзакционный стаб с plugs) |
| 7 | §8.1 п.2 | read_device_id один раз | на проводе q-флоу даёт множественные чтения @0xf0014 (5–9 на сценарий) | несколько dm-слоёв независимо зовут dm_get_device_id/read_device_id (mopen-probe, FwCompsMgr, get_dev_info, trm_create, guard, icmd_init_cr) — это НЕ ретраи (все успешны, по одному на слой); §2-свойство «ретраев нет» не нарушается |
| 8 | §3 п.5 | retry «до 100 итераций × 10 мс» | ровно 100 ретраев на проводе, затем отказ | do/while в `change_i2c_secondary_address` (refs :2991-3004 ≈ build :2992-3004): 1 предварительное чтение + 100 в цикле — счёт сходится с транскриптом s8 (102 I2C_RDWR) |

### 12.4 Refs (a2b9858b) vs сборка (1b8ac4b5)

По всем затронутым эмпирикой функциям расхождений НЕТ: фрейминг
`mtcr_i2c_mread4/mwrite4` (build mtcr_ul_com.c:2624-2698 = refs :2624-2698),
`change_i2c_secondary_address` (build :2939-3010 ≈ refs :2939-3010 —
структура и константы идентичны), `icmd_init_cr`/`get_version`
(CX4-ветка: cmd_ptr=hcr=0x0), GW-константы mflash_pack_layer.h:325-329
(0xf0404/0xf0408/0xf040c/0xf0420 — в обоих деревьях идентичны),
`connectib_flash_lock`/`check_cache_replacement_guard`/`mf_open_fw`
(адреса и порядок операций совпадают; строки чуть смещены — пины §1–§9
остаются по refs). Единственная «новизна» — адрес 0xf0420 — омиссия
канона §7.1/§7.3, не различие версий (обе дают одно и то же).

### 12.5 Наблюдаемая граница на стабе (§8.6-контракт, фиксация)

- **Проходит FW-less (чистые §2-транзакции)**: open+probe+sec-addr §1/§3
  (все ветки, включая 0x48→0x47 и 100-retry), read_device_id, CR-read/write
  утилитами, cache-rep guard-чтения, GW-семафор poll, GW ADDR/CMD записи,
  GW DATA чтения (RDID), unlock/restore — всё в транскриптах s1–s10.
- **Останавливается (FW-зависимые ответы)**: (а) ICMD version-гейт —
  версионное чтение @cmd_ptr/hcr возвращает мусор → весь ICMD/MCC-путь и
  guard-индуцированный icmd_init отказывают ДО семафора/mailbox
  (подтверждён порядок §7.5: версия раньше семафора); (б) jedec RDID —
  данные от «flash» → идентификация flash-типа падает на первом RDID, до
  WREN/RDSR/RES; (в) block-write §2.4 — недостижим без FW (п.12.3-6).
- Поведение NACK/тайминги реальной шины, сходимость retry-цикла, live
  границы MCC — остаются live-циклом 2 (§6, §9.3) — офлайн-стаб их не
  моделирует и не опровергает.
