# 140. Апгрейд FW CX-4: single-port 12.28.4706 (основной) + 14.32 Lx (отложен)

Дата: 2026-09-07. Статус: **выполнено.** Образ **v2** (4706 single-port) прошит
на карту и **работает**: single-port, running FW `12.28.4706`, PCIe x16, линки
**100G + 56G** по оптике и DAC (блок **ИТОГ** выше). Альтернатива (14.32 Lx, §8)
— **отложена**
по решению владельца: «чипы разные, скорее не стартанет».

Метод: офлайн-разбор образов (`scripts/probes/toc_probe.py`,
`scripts/probes/graft_4706.py`, `scripts/probes/upgrade_base.py`), байт-diff
A↔C и трёхсторонний A/C/G, сборка гибрида + пересчёт CRC. Теория формата/CRC/
FNP — `docs/250-re/100-formats/025-crc.md`, `docs/250-re/130-cable-gate/015-speed-bits.md`, `docs/250-re/110-signing/030-root-of-trust.md`, процедура кросс-флеша — `docs/850-howto/100-cross-flash-ops`. Каждое утверждение —
с источником (смещение, md5, вывод).

---

## ИТОГ (флеш + тесты, 2026-09-07) — v2 single-port 4706 **РАБОТАЕТ**

**v1** (точечные правки §3: `lcl[1]`, PCIe width, `num_ports`, …) прошит →
**dual-port bug**: `0x11:0x35` (SKU 0x13/0x14) и др. port-поля не перенесены →
карта грузится как 2-портная, фантомный port2 (`42:00.1`) без backplane → FW
health err `synd 0x7 (irisc not responding)`; warm-reboot → FW **hang в
«pre-initializing»** (`mlx5_init_one -110`, нет netdev) → unusable.

**v2** (фикс): `graft_4706.py` → копия **ВСЕХ** config-секций A
(`0x08/0x09/0x11/0x12`) целиком + `lcl[0]=0xfb` (56G) + `0x10` sub/PSID ← A.
Образ `/tmp/cx4_4706_sp_v2.bin` (md5 `9ac17476e5211541e4b92d8e35997a58`),
config-секции == A (кроме `0x12:0x30b` bb→fb), `num_of_ports=1`, SKU `0x13`.

**Флеш**: plain `burn` **FAILS** — `The Digest in the signature is wrong`
(`FWCOMPS_MCC_ERR_REJECTED_DIGEST_ERR`; проверку делает FW через MCC-регистр).
Обход: `mstflint -d 42:00.0 -i … --no_fw_ctrl -y burn` (прямой путь во flash,
«without signatures»). **`-a/-p/-c` — НЕВАЛИДНЫЕ флаги** (в старом плане §7 были
ошибочно). Застрявшую v1-карту (FW hang) спас **cold boot** (power-cycle от
розетки, как с HPE); по окну, когда v1 поднялся, прошит v2.

**Результат (v2, после reboot):**
- single-port: **только `42:00.0`** (нет `42:00.1`) ✓
- running FW **`12.28.4706`** (devlink `dev info`), stored 4706, PSID
  `MT_2180110032` ✓ — (dmesg/ethtool `-i` показывали `2302`; тогда
  объясняли «stale от boot-крэша» — **неверно**, root cause: §11)
- PCIe **x16** ✓
- boot-assert `synd 0x1`/ext `0x8949`/irisc 4 — **повторяется каждый чистый
  boot** (тот же ext_synd, `raw fw_ver 0xc01c08fe`), но FW **recovered**, health
  count стабилен (38), все линки работают. **Причина НЕ установлена** — не факт,
  что от нашего патча; возможно pre-existing (в 2302 или в 4706-базе C). Опциональная
  проверка — в блоке ниже.
- **Линки (все UP)**: оптика 100G + 56G (force autoneg); **DAC 56G**
  (Mellanox `670759-B22`) → 56G; **DAC 100G** (`QSFP-100G-CU1M`) → 100G
- **56G (ранее невозможно на 2302) теперь работает** — ядро цели ✓

---

## 0. TL;DR

1. Задача (уточнена владельцем, 2026-09-07): взять **A** = `12_28_2302`
   MCX455A (single-port, наша карта, последний стоковый FW от Mellanox/NVIDIA)
   → разрешить 56G, и перенести **обновлённый код из C** = `12_28_4706` MCX456A
   (dual-port, поновее) в single-port. **CX-4Lx (14.32, 0x1015) — отложить**
   (другой чип, не стартанет).
2. Ключевое: A и C — **один чип** (0x1013 / MT27700), **один релиз 12.28**,
   **одинаковый layout config-секций**. Но code-секции у C **больше**
   (MAIN_CODE `0x3090e0→0x30a590`) и смещены → «вырезать код из C и вставить в
   адреса A» **невозможно** (не влезет, §2).
3. Решение: **база = C** (self-consistent 4706 layout + новый код) +
   **переконфигурация под single-port из A** (lcl[1], PCIe width, port-count,
   HW_MAIN_CFG, identity) + 56G (lcl[0]=`0xfb`). Version-stamps держим C (4706).
4. Образ: `/tmp/cx4_4706_singleport.bin`, **md5 `4baf54f16fbab520e52b6d567cedca61`**,
   FW `12.28.4706`, `dev 0x1013`, `sub 0x0013`, `PSID MT_2180110032`,
   `lcl fb/00` (1p, 100G+56G), PCIe `x16`, CRC 0 mismatch (§3–§5).
5. Риск (осознанный): dual→single переконфигурация — могли пропустить
   port-поле; карта **non-secure**, откат безопасен (бэкап `ri` + FNP, §7).

---

## 1. Образы (инвентарь, md5 сверены 2026-09-07)

| Обозн. | Файл (`refs/fw/cx-4/`) | SKU | dev_id | sub | PSID | lcl | PCIe | md5 |
|---|---|---|---|---|---|---|---|---|
| **A** (наша, ref) | `fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-…102.bin` | 1p QSFP28 100G | `0x1013` | `0x0013` | `MT_2180110032` | `0xbb` | x16 | `b37620c0…` |
| **C** (база, код) | `fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-…103.bin` | 2p QSFP28 100G+56G | `0x1013` | `0x0014` | `MT_2190110032` | `0xfb` | x8 | `1289bec0…` |
| **built** (основной) | `/tmp/cx4_4706_singleport.bin` | 1p QSFP28 100G+56G | `0x1013` | `0x0013` | `MT_2180110032` | `0xfb`/`0x00` | x16 | **`4baf54f1…`** |
| G (alt, отложен) | `fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-…502.bin` | 1p QSFP28 50G (Lx) | `0x1015` | `0x0006` | `MT_2430110032` | `0x3b` | x8 | `098fa9c0…` |

`lcl` бит-карта (`docs/250-re/130-cable-gate/015-speed-bits.md`): `bit0=1G 1=10G 3=25G 4=40G 5=50G 6=56G
7=100G`. Цель `lcl[0]=0xfb`={1,10,25,40,50,56,100}; `lcl[1]=0x00` = port 2
отсутствует (single-port).

---

## 2. Почему не «вырезать код из C и вставить в A»

Сравнение ITOC-лейаутов A (2302) и C (4706):

- **Config-секции** (`0x08` HW_BOOT_CFG, `0x09` HW_MAIN_CFG, `0x11` FW_BOOT_CFG,
  `0x12` FW_MAIN_CFG, `0x10` IMAGE_INFO) — **одинаковые адреса и размеры** в A и
  C (оба 12.28, один чип) → сравнимы/переносимы байт-в-байт.
- **Code-секции** — **разные размеры и смещены** в C (4706):

| Секция | A addr/size | C addr/size |
|---|---|---|
| `0x03` MAIN_CODE | `0x157000` / `0x3090e0` | `0x159000` / `0x30a590` (+`0x14b0`) |
| `0x18` ROM_CODE | `0x072000` / `0xa9c28` | `0x072000` / `0xab228` (+`0x1600`) |
| `0x02` PCI_CODE | `0x12c000` / `0x2ab58` | `0x12e000` / `0x2ab38` |
| `0x05` IRON_PREP | `0x004000` / `0xe1fc` | `0x004000` / `0xe328` |

Код C не влезает в адреса/размеры A → прямой «вырез-и-вставка» невозможен.
Поэтому **база = C** (его код self-consistent в его layout), а single-port-конфиг
переносим из A в config-секции C. Финальный образ = «A-конфиг + код C» — тот
самый, что просил владелец.

---

## 3. Стратегия: база C + single-port конфиг A

Diff A↔C по config-секциям **очень чистый** (A=1p/2302/x16/100G, C=2p/4706/x8/
100G+56G). Разложение расхождений:

- **FW_MAIN_CFG (0x12)**: 12 байт. Порт-связан — только `lcl[1]@0x317`
  (A=`00`, C=`fb`). Остальные (`0x0072,0x0076,0x0077,0x007b,0x0283,0x02c4..7,
  0x05ac,0x05e7`) — version-stamps 2302↔4706.
- **HW_BOOT_CFG (0x08)**: `0x008b` = PCIe width (A=`09` x16, C=`89` x8);
  `0x0094–0x9f` — version (держать C).
- **FW_BOOT_CFG (0x11)**: port-count `0x0185` (1/2), `0x0195` (2/4), per-port
  таблица `0x02ef,0x2f6,0x30e,0x326,0x33e`; `0x0006–0x000f,0x001a,0x001b,0x0035`
  — version (держать C).
- **HW_MAIN_CFG (0x09)**: 55 байт — только module/serdes-таблицы (1 vs 2 порта),
  version-stamps **нет** → секция чисто card-specific.
- **IMAGE_INFO (0x10)**: identity (sub `0x0021`, PSID `0x0024`) + version-строки.

Правки (база C → single-port из A):

| Секция | rel | Было (C) | Стало | Источник |
|---|---|---|---|---|
| `0x12` FW_MAIN_CFG | `0x317` | `fb` | `00` | lit (port 2 off) |
| `0x08` HW_BOOT_CFG | `0x08b` | `89` | `09` | A (x16) |
| `0x11` FW_BOOT_CFG | `0x185` | `02` | `01` | A (num_ports) |
| `0x11` FW_BOOT_CFG | `0x195` | `04` | `02` | A |
| `0x11` FW_BOOT_CFG | `0x2ef` | `07` | `00` | A |
| `0x11` FW_BOOT_CFG | `0x2f6/0x30e/0x326/0x33e` | `80` | `c0` | A (×4) |
| `0x09` HW_MAIN_CFG | `0x0000` (вся, `0x1600`) | 2×QSFP28 | 1×QSFP28 | A (serdes 3,2,1,0) |
| `0x10` IMAGE_INFO | `0x021` | `14` | `13` | A (sub `0x0013`) |
| `0x10` IMAGE_INFO | `0x024` (14B) | `MT_219…` | `MT_218…` | A (PSID) |

`lcl[0]@0x30b` **остаётся C = `0xfb`** (100G+56G) — 56G уже разрешён в C.
`device_id@0x001c = 0x1013` — и в A, и в C, не меняется.

---

## 4. Сборка: `scripts/probes/graft_4706.py`

```
python3 scripts/probes/graft_4706.py \
  -b refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-…103.bin \
  -a refs/fw/cx-4/fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-…102.bin \
  -o /tmp/cx4_4706_singleport.bin
```

Алгоритм: (1) CRC-проверка **всех** секций базы C; (2) применение правок §3
(значения из A читаются по **его** flash-адресам); (3) пересчёт CRC изменённых
секций: `sec_crc=crc16(секция)` в bits 208..223 записи ITOC, затем
`entry_crc=crc16(запись[:28])` в bits 240..255 (`docs/250-re/100-formats/025-crc.md`); (4) self-
верификация. CRC-16: poly `0x100B`, init/XOR-out `0xFFFF`.

Вывод (CRC пересчёта):

```
0x08 HW_BOOT_CFG   sec_crc 0x1415->0x57a4  entry_crc 0x9b62->0x9d4b
0x09 HW_MAIN_CFG   sec_crc 0x04b3->0xd94b  entry_crc 0xe417->0x1287
0x10 IMAGE_INFO    sec_crc 0x3d68->0xc516  entry_crc 0xf74f->0xd617
0x11 FW_BOOT_CFG   sec_crc 0xf3dc->0x9df5  entry_crc 0x7017->0x8cf7
0x12 FW_MAIN_CFG   sec_crc 0xeff0->0xcfd8  entry_crc 0xace3->0x4ab0
```

---

## 5. Верификация (офлайн)

```
$ mstflint -i /tmp/cx4_4706_singleport.bin q
  Image type: FS3
  FW Version: 12.28.4706
  Product Version: rel-12_28_4706
  PSID: MT_2180110032
  Orig PSID: MT_2190110032
$ python3 scripts/probes/toc_probe.py /tmp/cx4_4706_singleport.bin
  header@0x2000: sig=ITOC OK ver=1   (0 CRC-BAD по всем секциям)
```

Байтовая сверка результата (abs-смещения в собранном образе):

| Поле | abs | Значение |
|---|---|---|
| device_id | `0x48101c` | `0x1013` |
| subsystem | `0x481020` | `0x0013` |
| PSID | `0x481024` | `MT_2180110032` |
| lcl[0] | `0x01430b` | `0xfb` (1,10,25,40,50,56,100G) |
| lcl[1] | `0x014317` | `0x00` (single-port) |
| PCIe width | `0x01808b` | `0x09` (x16) |

Размер = 16 744 768 B (16 МБ). `md5 4baf54f16fbab520e52b6d567cedca61`.

---

## 6. Риск и откат

- **dual→single переконфиг**: переносили port-count/lcl/HW_MAIN_CFG/PCIe по
  diff A↔C. Если пропущено port-поле → port 2 может «привидеться» или
  single-port сконфигурирован неполностью. Митигция: A (2302 single-port)
  уже работает на этой карте → single-port конфиг known-good.
- **Version-stamps**: держим C (4706) — не подменяли 2302-значения, кроме
  осознанных port-полей.
- **Откат безопасен**: non-secure; `FORBIDDEN_VER` = нули (откат на 2302/56G не
  запрещён); бэкап `ri` до флеша; FNP recovery принимает любой образ (`docs/850-howto/130-rom-dump`).

---

## 7. Флеш (выполнено, 2026-09-07) — фактическая процедура

> **Исправление** (было ошибочно): флаги `-a/-p/-c` в mstflint **не существуют**;
> plain `burn` **не проходит** (FW-проверка digesta через MCC → `The Digest in
> the signature is wrong`). Рабочий путь — **`--no_fw_ctrl`** (прямая запись во
> flash, «without signatures»). Подробности + исход — в блоке **ИТОГ** выше.

```
# 0) бэкап текущего flash (ri — позиционный аргумент файла, НЕ -o)
ssh root-mellanox 'mstflint -d 42:00.0 ri /var/roothome/cx4_backup_pre4706.bin'
# 1) доставка v2
scp /tmp/cx4_4706_sp_v2.bin root-mellanox:/var/roothome/
# 2) burn: --no_fw_ctrl (plain FAILS: MCC digest). ~5–7 мин (медленный flash-I/O;
#    timeout >= 450s, иначе обрыв на середине -> partial flash)
ssh root-mellanox 'mstflint -d 42:00.0 -i /var/roothome/cx4_4706_sp_v2.bin \
    --no_fw_ctrl -y burn'
# 3) reboot -> проверка
ssh root-mellanox 'mstflint -d 42:00.0 q'                 # FW 12.28.4706
# lspci -s 42:00                                      # ТОЛЬКО 42:00.0 (нет 42:00.1)
# devlink dev info pci/0000:42:00.0                   # running fw.version 12.28.4706
# ethtool enp66s0np0                                  # Speed 100000/56000 Mb/s
```

Откат (non-secure, FNP): `mstflint -d 42:00.0 -i /var/roothome/cx4_backup_pre4706.bin
--no_fw_ctrl -y burn` → reboot. Бэкап = оригинал `12.28.2302` (md5 `e84a4006…`).

---

## 8. Альтернатива: 14.32 Lx — **отложена** (чип другой)

Раньше рассматривался прыжок на `14.32.1912` (CX-4Lx, `0x1015`). Собран и
офлайн-верифицирован образ `/tmp/cx4_14_32_upgrade.bin` (md5
`68485c31ca6308235dd10b99dad8b5c1`, `scripts/probes/upgrade_base.py`): база
`G` (14.32, 1p QSFP28) + identity/lcl/PCIe. **Но** владелец: CX-4Lx — другой
чип, «скоро не стартанет» → **отложить**.

Собранное по 14.32 (на потом):
- Трёхсторонний diff A/C/G: `FW_MAIN_CFG` 267 diff (257 PORT_A = 0x1013-SKU,
  `A==C`), `KEEP_G`=version. Layout-shift 12.28→14.32: 0x06-speed-table
  `−0x6c`, module-table `−0x54` → целосекционный байт-порт небезопасен.
- Риск 14.32-образа: 0x1013 feature-table (`FW_MAIN_CFG 0x07cb+`, 257 байт) и
  VPI не перенесены (база EN).
- Вывод: если 4706-путь (§7) упрётся, вернуться к 14.32 с полным переносом
  feature-table — но сначала подтвердить, что 14.32 Lx вообще грузится на
  0x1013 (чип).

---

## 9. Выводы / дальше

1. **Выполнено**: свежий код **12.28.4706 перенесён** на single-port `0x1013`
   (v2 = база C + **все** config-секции A + 56G), прошит и **работает** —
   single-port, x16, линки 100G + 56G по оптике и DAC (блок **ИТОГ**, §7).
2. **Урок**: точечных port-правок (§3) **недостаточно** (v1: пропущен
   `0x11:0x35` и др. → dual-port bug). Надёжно — **целосекционный** перенос
   config-секций A (v2). A и C — один чип/релиз/layout config → перенос
   безопасен; код C self-consistent (прямая вставка в A невозможна — код больше).
3. **Флеш CX-4** (non-secure): plain `burn` не проходит (MCC digest) →
   **`--no_fw_ctrl`**. Застрявший FW-образ спасает **cold boot** (power-cycle).
4. 14.32 Lx отложен (чип другой) — образ и анализ сохранены (§8) на потом.
5. Дальше: фиксация сценария (v2 + `--no_fw_ctrl` + cold boot) в `docs/850-howto/100-cross-flash-ops`;
   разобраться с boot-assert `synd 0x1` (опционально, см. TODO; root cause
   расхождения версий 2302/4706 — §11, 2026-10-03).

---

## 10. Тесты линков (2026-09-07, v2 single-port)

Карта single-port (только `42:00.0`), running 4706, x16. Все линки через SN-2700.

### Матрица кабелей
| Кабель | 100G | 56G |
|---|---|---|
| Оптика 100G SR4 | ✓ (default) | ✓ (re-neg от карты) |
| DAC 100G (`QSFP-100G-CU1M` 1m) | ✓ | — |
| DAC 56G (Mellanox `670759-B22` 1m) | — (advertise 100G → down) | ✓ (`speed 56000`) |

### Поведение autoneg / скорости
- По умолчанию карта рекламирует **100G** (KR4/SR4/CR4/LR4); 56G — только через
  `ethtool -s speed 56000 autoneg on`. (Как на HPE-карте — «рекламирует максимум»
  **не** так: default = 100G.)
- `ethtool -s advertise <mask>` → **EOPNOTSUPP**: mlx5 здесь — только single-speed
  autoneg (`speed X`), не multi-speed mask.
- Re-negotiation: смена скорости на карте → линк пересохается (оптика 100G↔56G,
  DAC 56G↔100G); свитч в autoneg подстраивается без изменения на нём.
- 56G — только через autoneg (fixed 56G = «requires autoneg enabled»).

### No-touch (карту не трогаем)
- **FW персистит последнюю выставленную скорость через reboot** (не OS-config:
  NM/ifcfg пустые, device unmanaged) → «untouched» после boot = FW-сохранённая
  последняя скорость. Fresh default (никогда не трогал, первый v2-boot) = **100G**.
- No-touch тест: после reboot (последняя скорость = 56000) оптика **сама** сошлась
  на 56G, без `ethtool`.

---

## 11. Root cause: runtime `fw_ver 12.28.2302` при flash/devlink `4706` (разбор 2026-10-03)

Вопрос (владелец): dmesg health-блоки «жалуются» на `fw_ver 12.28.2302` —
версию, которой во флеше нет; mstflint q и devlink говорят `12.28.4706`.
Разбор: raw-дамп флеша + `mlxfwutil.py` + исходники kernel 7.2.x. Полный
журнал: `docs/superpowers/journal/2026-10-03-cx4-42-health-fwver.md` (шаги 1–5).

**Два независимых канала версии в драйвере** (kernel 7.2.5-200.fc44):

| Потребитель | Источник | Значение |
|---|---|---|
| dmesg probe, `ethtool -i`, ibstat, health-блок «fw_ver» | **initial segment** (BAR0+0, `iseg.fw_rev`/`cmdif_rev_fw_sub`), заполняет **работающий FW** | **12.28.2302** |
| health-блок «raw fw_ver 0xc01c08fe» | `iseg.health.fw_ver` (тоже заполняет работающий FW) | **12.28.2302** |
| `devlink dev info` running/stored | **реестр MCQI** (FW отчитывается о версии запущенного образа) | 12.28.4706 |
| `mstflint q` | IMAGE_INFO из флеша (офлайн) | 12.28.4706 |

Код: `driver.h:900-912` (fw_rev_* = `ioread32be` из `dev->iseg`),
`main.c:1102` (probe-строка, до поднимания cmd-interface), `en_ethtool.c:58`
(ethtool), `health.c:447` (health-блок — те же макросы, не поле буфера),
`fw.c:831` (devlink → MCQI), `mlx5_ifc.h:11430` (layout initial segment).

**Почему iseg-версия = 2302.** v2-образ = код C (4706) + **config-секции A
(2302) целиком** (стратегия 09-07, §3). Version-stamps 2302 в v2:

- `0x11 FW_BOOT_CFG[6:8] = 0x08fe` (subver **2302**; у C — `0x1262`/4706) +
  build `0x5502` + дата сборки `24.08.29` — **единственный версионный 2302 в
  config/identity-секциях образа**;
- `0x12 FW_MAIN_CFG` — 9 version-stamp-офсетов с значениями A (0x0072,
  0x0076-77, 0x007b, 0x0283, 0x02c4-c7, 0x0317, 0x05ac, 0x05e7);
- `0x08 HW_BOOT_CFG[0x94:0x9f]`, `0x09 HW_MAIN_CFG` — значения A.

`mlxfwutil.py diff`: 0x11/0x09/0x08 v2 **байт-в-байт == A**; 0x12 v2 отличается
от C ровно в stamp-офсетах; MAIN_CODE v2 == C. FW строит iseg/health-версию
из config-stamps, **не** из IMAGE_INFO (0x10 = 4706, C — по нему devlink/MCQI
и mstflint q). Образ 12.28.2302 во флеше **не существует** (slot A = T2
14.32, инвалидирован; slot B = v2) — 2302 «живёт» только как stamps в v2.

**boot-assert (`synd 0x1`/ext `0x8949`) — live, не stale-запись.** Паттерны
записи (callra `0x008041d8`, exit `0x008d3c0c`, vars `0x0002ab30/0x2ab38`,
fwver `0x0c1c08fe`, BE+LE) отсутствуют во всём 16MiB дампа; `0xE5 FW_NV_LOG`
пуст (MTCF-заголовок + стёртый регион). Запись создаётся **работающим v2 FW на
каждом power-on** (t=0, ранний init MAIN_CODE, код-офсет 0x41d8); драйверская
recovery (FW reset) перезагружает FW → Link up (~12 c на бут). «2302» в
блоке — iseg-версия, а не отдельное поле. Причина assert НЕ установлена
(кандидат: рассогласование 4706-код + 2302-config — не подтверждено RE).
irisc: в ИТОГ 09-07 «irisc 4», на всех свежих ботах **irisc_index 3** —
расхождение в доке.

**Корректировка интерпретации 09-07** (ИТОГ): «stale 2302 от boot-крэша» —
неверно; 2302 не артефакт — FW активно отчитывается этой версией (stamps из
графтного config A).

**Следствия (решение за владельцем):**
- Расхождение версий — косметика (код на карте 4706), но dmesg/ethtool/ibstat
  вводят в заблуждение (и мешали диагностике 09-14/09-19/10-03).
- boot-assert функционально безвреден (recovery, линки работают) — шум в dmesg.

**Сборка v3 (2026-10-03, решение владельца — фикс версионных полей):**
`mlxfwutil.py merge --base v2 --src C` со spec
`0x11+0x6+10, 0x11+0x1a+2, 0x12+0x72+1, 0x12+0x76+2, 0x12+0x7b+1, 0x12+0x283+1,
0x12+0x2c4+4, 0x12+0x5ac+1, 0x12+0x5e7+1, 0x08+0x94+12` → 31 версионный байт ← C,
port-поля A сохранены. **`cx4_4706_sp_v3.bin`, md5 `ffa2fadd8204b26e401f4ad90da9f5ed`**
(16744768 B; локально `refs/fw/cx-4/`, сервер `/var/roothome/`). Верификация:
`verify` PASS; `diff v2↔v3` = ровно эти 31 B; `diff C↔v3` = только A-port-поля
(SKU `0x11:0x35=13`, `0x11` port-поля, `0x12:0x317`, `0x08:0x8b`, `0x09` serdes,
`0x10` sub/PSID).
**Ловушка (зафиксирована)**: §3 классифицирует `0x11:0x35` как «version», но это
**SKU** (A=`13`/C=`14`) — поле, которое v1 не перенёс (ИТОГ). Первый spec с 0x35
дал образ с md5 `4baf54f1…` = md5 v1 (dual-port bug) — 0x35 исключено из spec.
Burn — владелец (`--no_fw_ctrl`, как v2); откат — v2
(`/var/roothome/cx4_4706_sp_v2.bin`).
**GUIDы**: 0xE0/0xE1 в v3 (как в v2) — нулевые guid/mac. Burn — **без**
`--ignore_dev_data` (default: device-data берётся с карты → `9440c9…` + MFG
`HP_2180110032` override_en=1 сохраняются; доказано бёрном 09-07).
`--ignore_dev_data` брать НЕЛЬЗЯ: device-data возьмётся из образа (нули) →
GUIDы сотрутся.

**Burn v3 (2026-10-03) — версия исправлена, но РЕГРЕССИЯ dual-port:**
`dmesg: firmware version: 12.28.4706` (root cause закрыт), НО `lspci` →
`42:00.0`+`42:00.1`, два netdev, порт 1 — фантом (`ethtool`: link modes
`Not reported`, `Speed: Unknown!`). Баг v1 вернулся.
**Вторая ловушка §3**: `0x11:0x1a..1b` (v2=`0c98`, v3=`0d18`) — **порт-поле**
(идентичность/число портов), а НЕ version. Корреляция на 7 CX4-образах:
`0c98`=single (MCX455A 2302, **MCX413A 4706**, MCX415A 2302), `0d18`=dual
(MCX456A-E/F, MCX416A). Явные port-поля (`0x35` SKU, `0x185` num_ports,
`0x317` lcl[1]) в v3 = A (single) и не в 31 байтах → culprit именно `0x1a..1b`,
перенесённый из C (dual).
**Сборка v4 (2026-10-03) — фикс**: v3 spec **без** `0x11+0x1a+2` (9 range,
29 байт): `0x11+0x6+10, 0x12+0x72+1, 0x12+0x76+2, 0x12+0x7b+1, 0x12+0x283+1,
0x12+0x2c4+4, 0x12+0x5ac+1, 0x12+0x5e7+1, 0x08+0x94+12`.
**`cx4_4706_sp_v4.bin`, md5 `63785adf3d32437fae0e2dbf9a8e61a4`**
(репо `refs/fw/cx-4/`, сервер `/var/roothome/`). `verify` PASS;
`diff v3↔v4` = ровно 2 байта `0x11+0x1a..1b`; subver=`1262` (4706),
PORT=`0c98` (single), SKU=`13`, num_ports=`01`. Burn v4 — владелец
(`--no_fw_ctrl`); откат — v2.
**Результат burn v4 (2026-10-03) — карта в норме**: single-port (только
`42:00.0`), **все источники версии совпадают** (`mstflint q`/`devlink`/
`ethtool -i`/`ibstat` = 12.28.4706), линк 100GbE up. Версионный симптом
(§11) и dual-port-регрессия v3 закрыты; **v4 — текущий рабочий образ**.
**Общий урок (→ docs/850-howto/120-field-merge)**: при graft config→version переносить ТОЛЬКО
версионные stamps; «версионные на вид» поля (`0x35` SKU, `0x1a..1b` порт) —
port-идентичность и ломают число портов.
