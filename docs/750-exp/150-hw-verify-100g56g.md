# 150. Железная проверка патча 56G: CX-4 (100G+56G) и CX-5/HPE (56G)

Дата: эксперименты 2026-09-06 → 2026-09-07, отчёт 2026-09-07.
Статус: **главная цель достигнута** — 100G + 56G на одной CX-4. Вторичная цель
(HPE CX-5 56G через FNP) — достигнута. Одно **важное замечание** про медные
DAC после патча (§5).

Метод: живые эксперименты на Mellanox-сервере (`root-mellanox`, реестр `HOST_MELLANOX_IP`).
Каждое утверждение — с источником: команда, md5, байтовое смещение или вывод
`ethtool`/`mstflint`. Теория (битовая карта, CRC, FNP, патч-тул) — `docs/250-re/130-cable-gate/015-speed-bits.md`, `docs/250-re/100-formats/025-crc.md`, `docs/850-howto/100-cross-flash-ops.md`, `docs/550-poc/100-mlxfwutil/040-probes-catalog.md`;
процедура кросс-флеша — `docs/850-howto/100-cross-flash-ops`.

---

## 0. TL;DR

1. **CX-4 (single-port 100G) — 100G + 56G на одной карте.** Однобайтовый патч
   `lcl[0] 0xbb→0xfb` (bit6=56G, `docs/250-re/130-cable-gate/015-speed-bits.md`) + CRC в стоковом образе
   MCX455A-ECA rel `12_28_2302` (PSID `MT_2180110032`) → карта поддерживает
   `56000baseKR4` и `100000baseKR4/SR4/CR4/LR4_ER4` одновременно (§2, §4).
   Карта **non-secure** → флеш без FNP, с `-apc` (§3).
2. **Линки CX-4 (патченная)**: 100G — оптика SR4; 56G — оптика SR4 и медь
   CR4 DAC (Mellanox `670759-B22`) — все link up (§4). 100G на 56G-only DAC —
   `Cable issue, Unsupported cable`.
3. **ВАЖНОЕ ЗАМЕЧАНИЕ (владелец, 2026-09-07):** после патча карты перестали
   признавать «родные» медные кабели, оптика работает. Нужен чистый A/B-тест
   (§5).
4. **HPE CX-5 (secure-fw)**: патченный образ без FNP → `Rejected
   authentication`; через FNP → 56G link up + 100G, PCIe Gen3 стабилен (§6).
5. **Аномалия PCIe Gen1 на HPE** — транзитная (live-вставка), не патч; после
   рефлеша + power cycle — Gen3 стабилен (§7).

---

## 1. Железо и образы

| | CX-4 (цель) | HPE CX-5 |
|---|---|---|
| PCI / if | `0000:42:00.0` / `enp66s0np0` | `0000:41:00.0` / `enp65s0f0np0` (+ `enp65s0f1np1`, без кабеля) |
| SKU | single-port 100GbE QSFP28 (MCX455A) | dual-port 100GbE QSFP28, HPE `872726-B21` (`refs/fw/cx-5-6/cx5-872726-HP-dc.ini`: `lcl[0]+lcl[1]`, `product_id 841QSFP28`) |
| PCIe | Gen3 x16 (`LnkCap`/`LnkSta` 8GT/s x16) | Gen3 x16 |
| Security | `N/A` (non-secure) | `secure-fw` |
| FW до работ | `12.28.4706` MCX456A-FCA (56G only, PSID `MT_2170111021`) — прошита владельцем для теста 56G | `16.35.4030` (PSID `HPE0000000009`, `Speed56Gb=0`) |

Образы (md5 сверены на сервере 2026-09-07):

| Образ | PSID | lcl | md5 |
|---|---|---|---|
| CX-4 оригинал `refs/fw/cx-4/fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-UEFI-14.21.17-FlexBoot-3.6.102.bin` | `MT_2180110032` | `0xbb` | (в репо) |
| **CX-4 патч** `/var/roothome/cx4_mcx455a_100g56g.bin` (локально `/tmp/cx4_mcx455a_100g56g.bin`) | `MT_2180110032` | `0xfb` | `f3efc54b23ad322666220185a7a8ae49` |
| MCX456A-ECA `12_28_4706` (нативные 100G+56G, не использован) | `MT_2190110032` | `0xfb` | `1289bec0…` (`/var/roothome/cx4_ecat_100g56g.bin`) |
| **HPE патч** `/var/roothome/hpe_card_patched.bin` | `HPE0000000009` | `0xbb→0xfb` (lcl[0]+lcl[1]) | `f5c8535a3b35dad55bd6a93579de7291` |
| HPE backup `/var/roothome/hpe_img_backup.bin` | `HPE0000000009` | `0xbb` | `4f783bbb640950ea015a8969df87cc5b` |

Свитч: порты форсируются (56G / 100G) владельцем; проверено в обоих режимах,
3 цикла переключения 09-07 (§4).

---

## 2. CX-4: патч

**Структура (проверено `patch_56g.py --analyze` по оригиналу, 2026-09-07):**
- FS3; `FW_MAIN_CFG` (`0x12`) @ `0x14000` size `0xc00`; `lcl[0]` rel `0x30b` →
  abs **`0x1430b`**.
- MCX455A — **single-port**: единственный `0xbb` в `FW_MAIN_CFG`, пары
  `lcl[1]` со стридом `0xC` нет → штатный `patch_56g.py --port both` не
  подходит (ищет пару); использован кастомный однобайтовый патч.

**Патч (всего 5 байт):**

| Байт (abs) | Было | Стало | Что |
|---|---|---|---|
| `0x1430b` | `0xbb` | `0xfb` | `lcl[0]`: +bit6=56G → {1,10,25,40,50,56,100}G |
| `0x207a..0x207b` | `0x1355` | `0x2232` | `sec_crc` (запись ITOC секции `0x12`, big-endian) |
| `0x207e..0x207f` | `0x849d` | `0x604b` | `entry_crc` (та же запись) |

CRC-16 (poly `0x100B`, init/XOR-out `0xFFFF`) и порядок (сначала `sec_crc`,
потом `entry_crc`) — `docs/250-re/100-formats/025-crc.md`.

**Верификация (воспроизводимо):**

```
$ python3 - <<'EOF'
orig = open('<оригинал>.bin','rb').read()
pat  = open('/tmp/cx4_mcx455a_100g56g.bin','rb').read()
print([hex(i) for i in range(len(orig)) if orig[i] != pat[i]])
# ['0x207a', '0x207b', '0x207e', '0x207f', '0x1430b']
EOF
$ python3 scripts/probes/toc_probe.py /tmp/cx4_mcx455a_100g56g.bin
# ITOC+DTOC: 0 MISMATCH
$ mstflint -i /tmp/cx4_mcx455a_100g56g.bin q    # читается, PSID intact
```

PRS-текст (секция `0x30`) намеренно не тронут: `mstflint dc` по патчу
по-прежнему показывает `Speed56Gb = 0` — ожидаемо (`docs/550-poc/100-mlxfwutil/040-probes-catalog.md`), рантайм
читает бинарную `FW_MAIN_CFG`.

---

## 3. CX-4: флеш (non-secure, без FNP)

- Смена PSID (карта `MT_2170111021` → образ `MT_2180110032`): флаг **`-apc`**
  (`--allow_psid_change`, шаг 5 `docs/850-howto/100-cross-flash-ops`; флаг указал владелец). `--psid` —
  только для livefish.
- 16 МБ FS3 шьётся **3–4 мин**; фоновый не обязателен, но foreground-burn убит
  SSH-таймаутом (первая попытка — прервана на 56%) → `nohup` + лог + поллинг.

```
scp /tmp/cx4_mcx455a_100g56g.bin root-mellanox:/var/roothome/
ssh root-mellanox 'nohup mstflint -d 42:00.0 -i /var/roothome/cx4_mcx455a_100g56g.bin \
    -apc -y burn > /var/roothome/cx4_burn.log 2>&1 &'
```

- Хвост лога: `Burning FW image without signatures - OK` →
  `Restoring signature - OK` (патч сломал RSA — ожидаемо, `docs/250-re/110-signing/030-root-of-trust.md`;
  non-secure не проверяет) → reboot для активации.
- После reboot: `mstflint -d 42:00.0 q` → FW `12.28.2302`, PSID
  `MT_2180110032`, Security `N/A`.

---

## 4. CX-4: результат — матрица линков

Supported после патча (`ethtool enp66s0np0`, 09-06 и 09-07):
`56000baseKR4` + `100000baseKR4/SR4/CR4/LR4_ER4` + `40000baseKR4/CR4/SR4/LR4`.

| Порт свитча | Кабель | Результат | Дата |
|---|---|---|---|
| 56G | Mellanox `670759-B22` (CR4 DAC, 14.1Gbps/lane — `ethtool -m`) | **56000Mb/s, link up** | 09-06 (сразу после патча+reboot; повторно после свапа кабелей) |
| 56G | оптика `QSFP28-100G-SR4` | **56000Mb/s, link up** | 09-06, 09-07 |
| 100G | оптика `QSFP28-100G-SR4` (`ethtool -s enp66s0np0 speed 100000 autoneg on`) | **100000Mb/s, link up** | 09-06, 09-07 |
| 100G | 56G-only DAC | `Cable issue, Unsupported cable` | 09-06 |

**Стабильность переключения (09-07, оба свитч-порта):** 56G (01:07) → 100G
(01:19) → 56G (01:23) — каждый раз обе карты link up, PCIe `LnkSta 8GT/s x16`
без деградации.

Замечание: **56G по оптике SR4 — наблюдается** (14.1Gbps/lane SerDes проходит
через модуль). Противоречит раннему допущению «56G = только KR4/CR4
электрика» — зафиксировано как факт, механизм не разбирался.

---

## 5. ВАЖНОЕ ЗАМЕЧАНИЕ: медные DAC после патча

**Наблюдение (владелец, 2026-09-07):** патч что-то ломает — карты перестают
признавать «родные» медные кабели (Mellanox `670759-B22`), но на оптике
работают.

**Нюанс хронологии:** сразу после патча+reboot (09-06) 56G на этом же DAC
работало (строка 1 таблицы §4); наблюдение сделано позже. Возможные
конфаундеры: режим свитч-порта (56G/100G), состояние autoneg, свап кабелей —
чистый тест не проводился.

**Гипотеза (обсуждение 09-06):** бит `lcl` — лишь флаг «скорость существует в
FW», а PHY-конфиг / cable-совместимость для режима лежат в других полях
`FW_MAIN_CFG`/HW-секций, которые патч не трогает.

**A/B-тест (план, для чистых данных):**
1. Непатченный MCX456A-FCA (56G-only, исходная карта) + DAC → линк?
2. Патченный MCX455A + тот же DAC, тот же свитч-порт (56G) → линк?
   Снять `ethtool -m`, `mlxlink -d 42:00.0 -c`, `dmesg`.
3. Контроль: та же пара с оптикой.

---

## 6. HPE CX-5: 56G через FNP

- Патч (по фактическому образу карты): `lcl[0]@0x43e173`, `lcl[1]@0x43e17f`
  (abs) `0xbb→0xfb` + `sec_crc`/`entry_crc` (оба байта — в образе есть пара).
- **Без FNP** (тот же PSID): `Writing Boot image component - OK`,
  `-E- Burning FS4 image failed: Rejected authentication` — secure-карта
  отклонила образ с битой сигнатурой. Контроль: backup-образ того же PSID
  (md5 `4f783bbb…`) без FNP шьётся → причина отклонения — сигнатура, не PSID.
- **Через FNP** (джампер + power cycle, карта `15b3:020d`):
  `mstflint -d 41:00.0 -i /var/roothome/hpe_card_patched.bin -y burn` → OK
  (09-07).
- Результат: FW `16.35.4030` (версионная строка патчем не меняется), PSID
  `HPE0000000009`; **56000Mb/s link up** на 56G-порту (оптика
  `QSFP-100G-SR4`), затем **100000Mb/s link up** на 100G-порту (09-07).
  PCIe `8GT/s x16`.

---

## 7. Аномалия PCIe Gen1 (HPE) — транзитная

После live-вставки HPE шёл на 2.5GT/s (Gen1) при `LnkCap 8GT/s x16` и
Gen4-слоте. Рефлеш на backup + power cycle → Gen3. Дальше (несколько
reboot'ов, переключения 56G↔100G) — `LnkSta 8GT/s x16` стабилен. Патч
трогает только `lcl`+CRC в `FW_MAIN_CFG` (§2/§6); PCIe-конфиг живёт в других
секциях (`HW_*_CFG`) и не изменялся → аномалия не от патча (PCIe training
после live-вставки).

---

## 8. Выводы

1. Патч 56G в стоковом single-port образе CX-4 **работает**: 5 байт
   (1 lcl + 4 CRC), non-secure → без FNP, `-apc` для PSID.
2. **Главная цель достигнута**: 100G + 56G на одной CX-4; 56G — по оптике SR4
   и (с оговоркой §5) по меди CR4.
3. Secure-карта: патченный образ — только через FNP; backup того же PSID —
   без FNP (проверка сигнатуры при загрузке, см. `docs/250-re/110-signing/030-root-of-trust.md`).
4. Открытый вопрос: **распознавание медных DAC после патча** (§5) — A/B-тест.

---

## 9. Дальше

- **Обновление FW** (задача владельца, 2026-09-07) — офлайн-разбор образов +
  байтовые патчи + CRC (формат/CRC — `docs/250-re/100-formats/`, FNP — `docs/850-howto/100-cross-flash-ops.md`):
  - **CX-4 (основной, см. `docs/850-howto/140-fw-upgrade`)**: перенос кода из C `12_28_4706`
    (dual-port MCX456A) в single-port A `12_28_2302` (наша карта) + 56G.
    Гибрид `0x1013` (1p, 100G+56G, x16) собран и офлайн-верифицирован
    (md5 `4baf54f1…`, `/tmp/cx4_4706_singleport.bin`); флеш — `docs/850-howto/140-fw-upgrade` §7.
  - CX-4Lx `14_32_1912` (0x1015) — **отложен** (чип другой, скорее не
    стартанет); анализ и образ сохранены в `docs/850-howto/140-fw-upgrade` §8.
  - CX-5/HPE: `16_35_4030` древняя → свежий `16_35.x` LTS.
- A/B-тест медных DAC (§5).
- (По успехе) — фиксация результатов в `docs/850-howto/100-cross-flash-ops` (сценарии фазы 4).
