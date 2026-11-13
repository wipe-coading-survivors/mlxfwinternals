# 160. HPE CX-5 (41:00.0): VPI + Gen4 + 56/100 — PRECHECK

> **ОТМЕТКА.** Precheck (предварительная разведка) перед решением по
> роадмапу. Факты верифицированы read-only (lspci / mstflint / mlxconfig /
> ibstat / ibnodes / офлайн-разбор образов `scripts/probes/`). Роадмап — **не
> принят** (§9). Теория формата/CRC — `docs/250-re/100-formats/`, FNP и кросс-флеш — `docs/850-howto/100-cross-flash-ops`,
> signing — `docs/250-re/110-signing/`. Каждое утверждение — с источником (md5, смещение, вывод).

Дата: 2026-09-07. Статус: **ЗАВЕРШЕНО (2026-09-07): §9.0 выполнен, образ A
(56G+Gen4) зашит через FNP, cold boot — `LnkSta 16GT/s x16` (Gen4 РАБОТАЕТ),
VPI (ETH 56G + IB Active) и 56G подтверждены, IB на фабрике (LID 8, ibnodes).
Все сомнения §7 сняты; RDMA-бенч `ib_write_bw` пройден
(**31.28 Gb/s average** = полный QDR-рейт, §10.8).**

**Исходная постановка (владелец):** на HPE-карту — (1) сохранить 56+100,
(2) «влить новый fw из CX-5 VPI», (3) «влить новый fw из CX-5 VPI ex; если не
прокатит — выставить PCIe Gen4 в образе (2)». Уточнение владельца: **VPI =
Virtual Protocol Interconnect** — карта работает и как Eth, и как IB
**одновременно** (порт1 ETH, порт2 IB). Образы «VPI» = `MCX556A-ECU` /
`MCX556A-EDA` (см. `refs/fw/cx-5-6/`, diff `MCX556A-C_D-dc.diff`).

---

## ИТОГ (precheck)

1. **VPI уже РАБОТАЕТ на текущем FW 4030 — graft VPI-кода НЕ нужен.** Порт1
   (ETH 56G Active) + порт2 (IB, после `opensm` → **Active**) одновременно;
   свитч Inviniscale-IV видит порт2 как CA «MT4119 ConnectX5». PRS (секция
   `0x30`) текущего 4030-образа **уже содержит** полный VPI-конфиг (оба порта
   `network_link_type_ib=1, eth=1`, default IB) — **идентичен** ECU-VPI (§2–§3).
2. **56+100 уже есть и активны.** 56G — патчен вчера (`hpe_card_patched.bin`,
   bit6=0x40 в `FW_MAIN_CFG`), порт1 = 56G; 100G — нативный (§4).
3. **Остаётся реально действующая часть — PCIe Gen4.** Карта сейчас **Gen3**
   (`LnkCap 8GT/s`, `pcie_max_speed_supported=0x7` в FW). На том же чипе
   (0x1017) Gen4 **возможен** (ex/non-ex — один и тот же кремний; владелец
   переливал non-secure карты в Gen4). Служебная карта `81:00.0` (CX-5 Ex,
   0x1019) в том же сервере уже **Gen4 (16GT/s)** → сервер поддерживает Gen4.
   Включение = патч **2 байта** (§5.3: `max_speed` 0x07→0x0F + `cap_index`
   0x45→0x47) в FW-образе + FNP-флеш.
4. **Карта `secure-fw`** → `ri` и unsigned-`burn` заблокированы; запись — через
   **FNP (life-flash, `15b3:020d`)** (`docs/850-howto/100-cross-flash-ops.md`). Бэкап флеша **уже есть**
   (`hpe_img_backup.bin`, §8).

---

## 1. Карта (идентичность)

| Поле | Значение | Источник |
|---|---|---|
| BDF | `0000:41:00.0` / `41:00.1` (2 порта) | `lspci -nnd 15b3:` |
| Чип | **MT27800 [ConnectX-5] `15b3:1017`** (device_id 4119 = 0x1017) | lspci / PRS `device_id` |
| PSID | **`HPE0000000009`**, **Orig PSID `DEL0000000004`** (бывшая Dell) | `mstflint -d 41:00.0 q` |
| Security | **`secure-fw`** | `mstflint q` |
| FW | **16.35.4030**, FS4, UEFI 14.29.15, PXE 3.6.902 | `mstflint q` |
| = stock-образу | **`872726-B21 …16_35_4030….signed.bin`** (UEFI/PXE совпадают) | `refs/fw/cx-5-6/` |
| GUID/MAC | Base GUID/MAC — реестр `CARD_HPE_CX516A_GUID`/`_MAC` | `mstflint q` |
| Опись | «HPE InfiniBand EDR/Ethernet 100Gb 2-port 841QSFP28 Adapter» | `mlxconfig q` |
| CAs / netdev | `mlx5_4`/`enp65s0f0np0` (port0), `mlx5_5`/`enp65s0f1np1` (port1) | ibstat |
| PCIe (сейчас) | **Gen3** `LnkCap 8GT/s x16`, `LnkSta 8GT/s x16`; `LnkCap2 2.5–8GT/s` | `lspci -vvv` |

---

## 2. VPI уже работает на 4030 (факт, тест владельца)

Владелец воткнул **порт2** HPE-карты в **IB QDR-свитч Inviniscale IV** и
запустил `opensm`. Вывод (toolbox `t-adm`):

**`ibstat` (GUID — реестр `CARD_HPE_CX516A_GUID`):**
```
CA 'mlx5_4'  (port0)            CA 'mlx5_5'  (port1)
  State: Active                   State: Active   (было Initializing → opensm)
  Rate: 56                        Rate: 40 (до opensm; см. консерн §7.6)
  Link layer: Ethernet            Link layer: InfiniBand
  Port GUID: ⟨реестр `CARD_HPE_CX516A_P0_PORT_GUID`⟩  Physical state: LinkUp
                                   Port GUID: ⟨реестр `CARD_HPE_CX516A_P1_GUID`⟩
```
**`ibnodes`:** `Ca 0x⟨реестр `CARD_HPE_CX516A_P1_GUID`⟩ ports 1 "MT4119 ConnectX5"` +
`Switch 0x⟨реестр `HOST_SWITCH_GUID`⟩ ports 36 "Infiniscale-IV"` — **свитч видит порт2
как CA.** `mlxconfig`: `LINK_TYPE_P1=ETH(2)`, `LINK_TYPE_P2=IB(1)` (per-port).

→ Порт0 = **ETH 56G Active**, порт1 = **IB Active** — **одновременно**. Это и
есть VPI. Работает на текущем 4030 без каких-либо изменений.

### 2.1 VPI-конфиг уже вшит в 4030

`scripts/probes/prs_probe.py` (декомпрессия секции `0x30`) — PRS текущего
`hpe_img_backup.bin` (4030) **идентичен** ECU-VPI по VPI-полям:

| поле | HPE 4030 | ECU VPI 1012 |
|---|---|---|
| `port[0/1].vpi.network_link_type_ib/eth` | **1 / 1** | 1 / 1 |
| `port[0/1].vpi.default_link_type_ib/eth` | 1 / 0 | 1 / 0 |
| `multi_function.num_of_ports` | 2 | 2 |
| `lcl[].eth_speeds` (56 / 100) | **56=0** / 100=1 (`0xbb`) | 56=0 / 100=1 |
| `pcie_max_speed_supported` | `0x7` (Gen3) | `0x7` (Gen3) |
| `device_id` / subsystem | 4119 / `0x0256` | 4119 / `0x0124` |
| PSID / SRIOV | HPE0000000009 / `sriov_en=1` | MT_0000000504 / нет |

Отличия HPE-4030 от ECU-1012: **только** версия (4030 vs 1012), PSID/subsystem
(HPE vs MT_), SRIOV. **VPI-конфиг совпадает** → «вшивать VPI-конфиг» нечего.

---

## 3. «VPI = код или конфиг» (гипотеза; проверка отложена до §9.0)

Владелец: есть 2 VPI-прошивки (ex/non-ex) и 2 EN-прошивки (ex/non-ex).
**Гипотеза владельца: VPI и EN одной версии отличаются КОНФИГОМ (не кодом)** —
но не точно. Метод проверки: вырезать из образа **только базовую часть**
(config-секции, section-relative — см. подход
`refs/src/Mellanox-ConnectX-5-PCIe-Gen-4-Enablement`, `TECHNICAL.md`
«Section-Relative Addressing») и сравнить VPI↔EN **одной версии**. Прошивки
доступны публично (CX-5 InfiniBand = VPI / CX-5 Ethernet = EN).

**По этой карте:** вопрос снимается фактом (§2) — 4030-HPE-сборка **уже тянет
IB**, т.е. не «EN-only». Гипотезу «код vs конфиг» **проверяем не сейчас** —
когда сведём все сомнения (§7 → §9.0). Если бы карта была EN-only, путь =
graft **базовой части** VPI/IB-белда **той же версии** (4030, не 1012 —
downgrade + потеря HPE-PSID).

---

## 4. 56+100 (уже есть)

- **56G:** патчен вчера — `lcl[] 0xbb→0xfb` (bit6=`0x40`) в бинарной
  `FW_MAIN_CFG` (`0x12`) + пересчёт `sec_crc`/`entry_crc` (`docs/250-re/100-formats/025-crc.md`,
  `patch_56g.py`). RSA-подпись при этом ломается (ключ NVIDIA, `docs/250-re/110-signing/010-payload.md`).
  Артефакты: `hpe_card_patched.bin`, `hpe_872726_patched_56g.bin` (§8). Порт0
  реально на **56G** (§2).
- **100G:** нативный (bit7), без патча.
- ИТОГ: «56+100» **сохранено** — ничего дополнительно делать не нужно.

---

## 5. PCIe Gen4 (единственная реально действующая часть)

### 5.1 Бейслинх
- **41:00.0 (наша):** `LnkCap 8GT/s (Gen3) x16`, `LnkSta 8GT/s` — **Gen3**.
- **81:00.0 (CX-5 Ex, 0x1019, тот же сервер):** `LnkCap 16GT/s (Gen4)`,
  `LnkSta 16GT/s` — сервер **поддерживает Gen4**.

### 5.2 Почему сейчас Gen3 и как включить
Текущий 4030-образ несёт `pcie_cfg.pcie_max_speed_supported = 0x7` (Gen3)
(PRS `[hw_main_config]`). Gen4 = `0xf`. ex/non-ex — **один и тот же чип**
(0x1017); «Ex» — маркетинг/конфиг, не кремний. Владелец подтверждает:
non-secure карты переливал в Gen4 легко. → Включение Gen4 = **патч образа**:
`pcie_max_speed_supported 0x7→0xf` (+ сохранить 56G-бит + HPE-PSID), пересчёт
CRC, **FNP-флеш**, cold boot.

### 5.3 Локация Gen4-поля (задана тулом; верификация на образе — §9.0)
Источник — `refs/src/Mellanox-ConnectX-5-PCIe-Gen-4-Enablement` (`TECHNICAL.md`).
Для **QSFP28** (наш случай) Gen4 = **ровно 2 байта**, section-relative
(version-independent):

| Поле | Секция + оффсет | Gen3 → Gen4 |
|---|---|---|
| `max_speed` = `pcie_max_speed_supported` (единственное видимое в `mstflint dc`) | `HW_BOOT_CFG`(`0x08`)+`0x0023` | `0x07` → `0x0F` |
| `cap_index` (найдено binary-diff'ом) | `FW_BOOT_CFG`(`0x11`)+`0x0093` | `0x45` → `0x47` |

(Для SFP28 дополнительно `port_gen`/`speed_tbl`. Уточнение по нашему образу,
измерено 2026-09-07 `--analyze`: `port_gen=0x04` на обоих портах,
`speed_tbl=0x0FFF` — тул классифицирует образ по SFP28-паттерну; у
MT_-референсов VPI (`MCX556A-ECU/EDA`) `port_gen=0x06`. На практике
безразлично: оба байта **не трогаются**, патч остаётся ровно 2 байта.)

**ВЕРИФИЦИРОВАНО на нашем образе (2026-09-07, §10):** ITOC:
`HW_BOOT_CFG` @ `0x43f808`, `FW_BOOT_CFG` @ `0x43e9c8`. Абсолютные оффсеты:
`max_speed` @ `0x43f82b` = **`0x07`** ✓, `cap_index` @ `0x43ea5b` = **`0x45`** ✓
(двумя независимыми способами: `--analyze` тула и `xxd` по ITOC-оффсетам).
CRC — `docs/250-re/100-formats/025-crc.md`.

---

## 6. secure-fw + FNP (механизм записи)

- `ri` — **не работает** («Read image is not supported»); unsigned-`burn` —
  отклоняется. (`docs/250-re/110-signing/065-secure-fw-bit.md`: `secure-fw` = `MGIR.fw_info.secured`.)
- **FNP / life-flash** (`15b3:020d`): штатный способ записи **любого** образа
  (даже с битой RSA / чужим PSID). Джампер FNP (или SPI-пины 2+4) на включении
  → recovery → `mstflint -d <dev> -i out.bin burn` → cold boot (`docs/850-howto/100-cross-flash-ops.md`). **FNP — механизм записи, не обход проверки при загрузке** (§7).
- **Бэкап уже есть** (`hpe_img_backup.bin`, §8) — откат возможен.

---

## 7. Консерны / открытые вопросы (мои)

Статус на 2026-09-07 (после §10, **включая post-boot §10.8**): **снято 8 из 8**,
включая RDMA-бенч (`ib_write_bw` 31.28 Gb/s = полный QDR-рейт).

1. **Бинарная локация Gen4-поля** — **СНЯТО** (§10.1): `--analyze` + `xxd` по
   ITOC-оффсетам; значения `0x07`/`0x45` подтверждены в бинаре; итоговый diff
   патча = ровно 4 data-байта + 12 ITOC-CRC-байтов (§10.3).
2. **Gen4-способность именно слота 41:00.0** — **СНЯТО** (§10.2): upstream
   host-bridge `40:01.1` — `LnkCap: Speed 16GT/s, Width x16`,
   `LnkCap2: 2.5–16GT/s`. Слот Gen4-способен.
3. **Доступ к FNP** — **СНЯТО** (§10.4): карта переведена в FNP владельцем
   (2026-09-07, `41:00.0` = `15b3:020d`); FNP-запись на этой карте уже
   доказана вчерашним 56G-флешем.
4. **Загрузится ли образ с битой RSA** — **СНЯТО на этой карте** (§10.5):
   карта вчера работала на 56G-образе, чья RSA **уже битая** (stock-PRS
   `Speed56Gb=0` → 56G в стоке невозможен; `ibstat` §2 — `Rate: 56`).
   Т.е. HPE-PSID-карта с битой RSA **загружается** (эмпирика (A) из
   `docs/250-re/110-signing/030-root-of-trust.md` — подтверждена именно для этой карты/PSID).
5. **IB data-path** — **СНЯТО (2026-09-07, после cold boot)** (§10.8):
   ipoib-пинг через фабрику 3/3 (RTT ~0.1–0.9ms); `ibnodes` — порт виден как
   CA; SM работает на peer-узле; **`ib_write_bw` (RDMA Write, RC, 65536B):
   31.28 Gb/s average — полный QDR-рейт**.
6. **`Rate: 40` на IB-порту** — **СНЯТО (2026-09-07)** (§10.8): это **реальный
   рейт QDR-линка**, не placeholder: `40 Gb/sec (4X QDR)` = сырые 4×10GT/s
   (kernel/sysfs и `ibstat` отчитывают raw; маркетинговое «10Gb/s QDR» —
   тот же линк). После LID (0x8) значение не меняется.
7. **PSID-идентичность при рефлеше** — **СНЯТО** (§10.3): diff финального
   образа против бэкапа — 16 байтов, PSID `HPE0000000009` на месте; 56G и
   Gen4 — в одном образе (один флеш).
8. **База = HPE 4030 (`872726`)** — решение, без изменений (выполнено: база
   бэкап-образа, §10.3).

---

## 8. Артефакты (на сервере `root-mellanox` + refs)

| Файл | Что | md5 |
|---|---|---|
| `/var/roothome/hpe_img_backup.bin` | **бэкап флеша** карты (4030) — точка отката | `4f783bbb640950ea015a8969df87cc5b` |
| `/var/roothome/hpe_card_patched.bin` | карта, патч 56G (базовал финальный образ) | `f5c8535a3b35dad55bd6a93579de7291` |
| `/var/roothome/hpe_872726_patched_56g.bin` | `872726` 4030 + 56G | `2a3f186190c2e673b8d0a6fc6c1b4f79` |
| `/var/roothome/hpe_final_56g_gen4.bin` | **финальный: 4030 + 56G + Gen4** — зашит 2026-09-07 (§10) | `e6a8517230586d949bf1ed19037be4c7` |
| `/var/roothome/hpe_q.txt` | `mstflint q` (PSID/Orig/secure) | — |
| `/var/roothome/hpe_cx5_backup.bin` | **0 байт** — неудачная `ri` (2026-09-07 12:17; `ri` на secure-карте не работает, как и ожидается) | — |
| `refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin` | **stock 4030** (= текущий FW карты) | — |
| `refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX556A-ECU_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin` | VPI (0x1017, Gen3, 1012) — референс | — |
| `refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX556A-EDA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin` | VPI ex (0x1019, Gen4, 1012) — референс | — |
| `refs/fw/cx-5-6/MCX556A-{ECU,EDA}_Ax_Bx-dc.ini`, `MCX556A-C_D-dc.diff` | PRS-конфиг VPI + diff C↔D | — |
| `refs/dumps/oprom-0000-41-00-0-2026-09-28.bin` | sysfs-ROM карты 41:00.0 (457728 B) = упакованная секция ROM_CODE флеша байт-в-байт (§11) | `f85c74af0c1e0d0117d5abb58c5f910e` |
| `refs/dumps/oprom-0000-81-00-0-2026-09-28.bin` | sysfs-ROM EX-карты 81:00.0 (169472 B): BAR отдаёт только img0+img1, UEFI-суб-образ не отдаётся (§11.2) | `31210dfae2b424563c88d1944de95a9f` |
| `refs/dumps/cx5_ex_nonsec_flash.bin` | старый флеш-дамп 81:00.0 (эпоха UEFI 14.28.x) — **эндьян-испорчен** (u32-byteswap): перед использованием byteswap каждых 4 байт (верифицировано 2026-09-28: после byteswap — валидные MTFW/структуры; ROM_CODE @0x43f990) | — |
| `scripts/probes/toc_probe.py`, `patch_56g.py` (репо, хост) | парсер ITOC/DTOC, патч 56G | — |
| `/tmp/prs_probe.py` (**на хосте**, не на сервере) | PRS-пробник (декомпрессия секции `0x30`) | — |

---

## 9. Варианты роадмапа (решение TBD)

- **0 (снять все сомнения — до любого флеша):** по пунктам **§7** снять
  **все** сомнения, зафиксированные в документе; новые, если возникнут по
  ходу, — дописывать в §7 и снимать так же. Пример: **перешить HPE-карту в её
  оригинальный FW** (бэкап `hpe_img_backup.bin`, §8) — одним махом снимает
  несколько вопросов (secure/PSID/VPI/Gen4-бейслинх на известном образе).
  Плюс сюда: `--analyze` Gen4-тула (§5.3/§7.1), проверка Gen4-слота 41:00.0,
  доступ к FNP, IB data-path (§7.2–7.5).
- **A (минимально, рекомендую для оценки):** на базе **HPE 4030 (`872726`)**
  патчить **только Gen4** (`pcie_max_speed 0x7→0xf`), сохранив 56G-бит + HPE-PSID
  → пересчёт CRC → FNP-флеш → cold boot → проверить `LnkSta 16GT/s` + VPI
  (ETH+IB) + 56/100. VPI и 56/100 уже работают — меняется только PCIe.
- **B:** как A + end-to-end IB-тест (`ib_write_bw`/`ibping` с peer) до/после.
- **C (если захочется «чистый» VPI/IB-белд):** база = публичный CX-5
  **InfiniBand (VPI)** белд **версии 4030** (не 1012) — но теряется HPE-PSID
  (нужен re-PSID). Вероятно **не нужно**: 4030 уже делает VPI (§2).
- **Порядок:** сначала **§9.0** (снять все сомнения из §7), потом A/B/C.

**Статус 2026-09-07:** §9.0 выполнен (кроме boot-зависимых #5/#6), **A
выполнен до cold boot**: образ `hpe_final_56g_gen4.bin` зашит через FNP
(§10). Дальше: cold boot → верификация → B (IB end-to-end, нужен peer).

---

## 10. Лог §9.0 + флеш (2026-09-07)

Практическая проверка всех пунктов §7. Карта на время работы — в **FNP**
(`41:00.0` = `15b3:020d`), переведена владельцем.

### 10.1 Gen4-локация на образе (был §7.1, Блок №1)

- ITOC (бэкап): `HW_BOOT_CFG(0x08)` @ `0x43f808`, `FW_BOOT_CFG(0x11)` @
  `0x43e9c8` → абсолютные оффсеты `0x43f82b` / `0x43ea5b` (§5.3, «≈» — точные).
- `xxd` по этим оффсетам: `0x07` и `0x45` — **совпадение** с ожидаемыми.
- `cx5_gen4_enable.py --analyze` (v1.1.0): те же значения, section-relative
  оффсеты совпали. В `hpe_card_patched.bin` (56G-база) — тоже `0x07`/`0x45`
  (56G-патч Gen4-поля не трогает).
- Примечание: VERSION-константа скрипта — 1.1.0, при том что CHANGELOG
  ведётся до 1.2.0 (HPE-OEM-детекции в скрипте нет: «OEM: Stock Mellanox» при
  PSID `HPE0000000009`). На патч не влияет (верифицировано diff'ом, §10.3).
- Примечание: тул классифицирует наш образ как «SFP28» (`port_gen=0x04`);
  MT_-VPI-референсы — `0x06` (QSFP28). См. уточнение в §5.3; патч = 2 байта.

### 10.2 Gen4-способность слота (был §7.2)

Upstream от `41:00.0` — host-bridge `0000:40:01.1` (AMD Starship/Matisse):
`LnkCap: Speed 16GT/s, Width x16`, `LnkCap2: Supported Link Speeds: 2.5–16GT/s`.
**Слот Gen4-способен** → после патча ожидаем `min(16, 16) = 16GT/s`.
(`LnkSta 2.5GT/s` в момент проверки — норма: FNP-recovery работает на Gen1.)

### 10.3 Финальный образ: 56G + Gen4 в одном (были §7.7/§7.8)

База — `hpe_card_patched.bin` (= бэкап + 56G). Поверх — Gen4-патч тулом.

- **Diff финал ↔ бэкап: ровно 16 байтов.**
  - `0x43e173`/`0x43e17f`: `bb→fb` — 56G-бит в `lcl[0]`/`lcl[1]` (`FW_MAIN_CFG+0x2ab`);
  - `0x43ea5b`: `45→47` — `cap_index` (`FW_BOOT_CFG+0x93`);
  - `0x43f82b`: `07→0f` — `max_speed` (`HW_BOOT_CFG+0x23`);
  - 12 CRC-байтов в ITOC — ровно по трём затронутым записям
    (`FW_MAIN_CFG`, `FW_BOOT_CFG`, `HW_BOOT_CFG`): `sec_crc`(entry+26) +
    `entry_crc`(entry+30).
- PSID `HPE0000000009` — **не тронут** (и в diff, и `strings`).
- Все 32 `sec_crc` (ITOC+DTOC) в финальном образе — **OK** (`toc_probe`).
- Проверка 56G-бита: `lcl`-пара `0xbb`→`0xfb` (стрид `0xC`) — бэкап vs патч.

### 10.4 FNP (был §7.3)

Карта в `15b3:020d` (FNP) — джампер работает. FNP-запись на этой карте
доказана заранее: вчера 56G-образ (чужая подпись) записан только через FNP
(unsigned-`burn` и `ri` на secure-карте отклоняются; сегодня повторная
попытка `ri` → пустой файл, см. §8).

### 10.5 RSA при загрузке (был §7.4)

До флеша снят фактом: стоковый 4030 **не поддерживает 56G**
(PRS-бэкапа `Speed56Gb=0`), а вчера порт0 шёл на **56G** (§2) → карта работала
на образе с **битой RSA**. Вывод: ROM этой карты (HPE-PSID, secure-fw)
загружает модифицированный образ (эмпирика (A) из `docs/250-re/110-signing/030-root-of-trust.md` для этой
карты). Остаточный вопрос «что именно проверяет ROM» — для `docs/850-howto/130-rom-dump`,
на наш путь не влияет.

### 10.6 Флеш (выполнено 2026-09-07)

```
mstflint -d 41:00.0 -i /var/roothome/hpe_final_56g_gen4.bin -y burn
  Burning FW image without signatures - OK
  -W- Failed to update FW boot address. Power cycle the device ...
  Restoring signature - OK
  -I- To load new FW, issue system-level reset.
```
Предупреждение «Failed to update FW boot address» в recovery — штатное
(обновится после power cycle). **Дальше только владельцу:** снять FNP-джампер
→ **холодный** power cycle (не reboot) → верификация ниже.

**Чем НЕ проверяется:** `mstflint dc` (и `-i <file>`, и `-d <recovery>`)
читает **PRS-текст секции `0x30`**, а не бинарный `FW_MAIN_CFG`/`HW_BOOT_CFG`:
`hpe_card_patched.bin` (известно работающий на 56G) в `dc` показывает
`Speed56Gb=0x0` — как и стоковый. Т.е. патченные байты `dc` **не видны**;
верификация патчей — только по линку после загрузки.

### 10.7 Верификация после cold boot (чек-лист)

1. `lspci -nnd 15b3:1017` — карта вернулась из `020d`; `lspci -vvv -s 41:00.0`:
   **`LnkSta: Speed 16GT/s, Width x16`** (главная цель).
2. `mstflint -d 41:00.0 q` — FW 16.35.4030, PSID `HPE0000000009`, secure-fw.
3. VPI: порт0 ETH (**56G** — доказательство 56G-бита), порт1 IB; `opensm`
   (поставить на сервер) → порт1 **Active**, `ibstat` — **`Rate: 10`** (QDR;
   снимает §7.6).
4. 100G: переключение/автопереговоры на 100G (нативный бит).
5. IB end-to-end (§7.5, roadmap B): `ib_write_bw`/`ibping` с peer по
   Inviniscale-IV — **нужен второй IB-узел** (на сервере IB-пиров нет: все
   mlx5 — Ethernet; вопрос владельцу).
6. Откат при неудаче: FNP-джампер → `mstflint -d <dev> -i
   /var/roothome/hpe_img_backup.bin -y burn` → cold boot.

### 10.8 Post-boot верификация (выполнено 2026-09-07, после FNP-снятия +
холодного power cycle владельцем)

**Результат: Gen4 РАБОТАЕТ, VPI жив, все пункты чек-листа зелёные.**

1. **Gen4 (главная цель):** `lspci -vvv -s 41:00.0`:
   `LnkCap: Speed 16GT/s, Width x16`, **`LnkSta: Speed 16GT/s, Width x16`**
   (было 8GT/s), `EqualizationComplete+`. Т.е. образ из флеша — именно
   финальный (Gen4-байты ни в одном другом образе нет).
2. **Идентичность:** `mstflint -d 41:00.0 q` — FW 16.35.4030, PSID
   `HPE0000000009`, secure-fw — сохранены.
3. **VPI одновременно:** `ibstat`: CA `mlx5_4` (port0) — **ETH, Rate: 56,
   Active**; CA `mlx5_5` (port1) — **InfiniBand, Rate: 40, Active, LID 0x8,
   SM LID 0x1**. Порт0: `enp65s0f0np0` speed = 56000 (56G-бит работает).
4. **IB-рейт (§7.6):** `rate: 40 Gb/sec (4X QDR)` — реальный рейт QDR
   (raw 4×10GT/s; «10Gb/s QDR» маркетинга = тот же линк). До и после LID —
   одинаковый: placeholder'ом не был.
5. **IB на фабрике:** peer-узел — реестр `HOST_PEER_P0_GUID` (порт2 —
   реестр `HOST_PEER_P1_GUID`, ipoib — реестр `HOST_MASTER_IPOIB_IP`/24) предоставляет SM
   (opensm; `ibnodes`: `master ibp1s0`, LID 1). На нашей стороне:
   `modprobe ib_ipoib` → `ibp65s0f1` (= `41:00.1`), реестр `HOST_MELLANOX_IPOIB_IP`/24,
   **пинг через IB 3/3, RTT 0.09–0.9ms**.
   `ibnodes` (с SM): `Ca 0x⟨реестр `CARD_HPE_CX516A_P1_GUID`⟩ "MT4119 ConnectX5"` — наш
   порт виден фабрикой (как в precheck §2), `Switch 0x⟨реестр
   `HOST_SWITCH_GUID`⟩ "Infiniscale-IV" (36 портов, LID 5)`.
6. **RDMA-бенч (#5) — пройден:** peer (`mlx4_0`, порт2, GUID —
   реестр `HOST_PEER_P1_GUID`) — server в цикле `ib_write_bw -d mlx4_0 -i 2`;
   наш сервер — клиент `ib_write_bw -d mlx5_5 <реестр `HOST_MASTER_IPOIB_IP`> --report_gbits`
   (наш порт — port1, `-i` = номер IB-порта). Результат:
   `65536B × 5000: BW peak 31.31, BW average 31.28 Gb/sec` (RC, MTU 2048,
   LID 0x08 ↔ 0x04) — полный QDR-рейт (40 raw − 8b/10b − заголовки IB).
7. **Инструменты:** штатный способ — **`t-adm` на сервере** (контейнер
   существует с 10 мес., `infiniband-diags` установлен внутри;
   `toolbox run -c t-adm bash -c 'ibstat; ibnodes'` — полный вывод выше).
   Нюансы: (а) `t-adm` на **хосте** фабрику сервера **не видит** — это другая
   машина (видит PCI хоста); (б) если `t-adm` на сервере **остановлен**
   (`podman ps` пуст) — fallback: one-shot
   `podman run --rm --privileged --entrypoint /bin/bash --net=host
   -v /sys/class/infiniband:/sys/class/infiniband:ro
   cr.getpods.ru/containers/toolbox:adm -c 'dnf install -y
   infiniband-diags; ibstat; ibnodes'` (`--privileged` обязателен: без него
   UMAD-порты дают I/O error). Именно так снимался первый post-boot-вывод
   (t-adm тогда был stopped; владельца запросом не беспокоили).

100G-бит (0x80) патчами не изменялся (0xbb→0xfb) — live-проверка не
проводилась (нужен 100G-link-partner); при необходимости — переключение
порта и линк-тест.

---

## 11. UEFI-POST-лог карты: где живёт (2026-09-28)

Постановка: карта при UEFI-загрузке печатает на VGA/SOL свой статус
(`Mellanox Driver: Starting device binding / Starting full FW initialization
/ … Checking FW image integrity / … Starting network init / Waiting for link
/ Logical Link is up`; двойной повтор = 2 порта/PF). На CX-4 с битой
прошивкой — `QueryClpCommands: Query failed (Status = 14)`. Исследование:
журналы `superpowers/journal/2026-09-28-hpe-uefi-post-log-section-re.md`
(офлайн-разбор), `2026-09-28-hpe-oprom-live-dump.md` (sysfs-ром, live),
`2026-09-28-oprom-img2-unpack.md` (распаковка img2).

1. **Это код UEFI-драйвера карты, не настройка.** Строки (UTF-16LE) — в
   PE32+ X64 драйвере **`Mlx5Nodnic`** внутри суб-образа **img2 секции 0x18
   ROM_CODE @0x4443d8** (img2 @+0x29600, 0x46600 → распакованный 0xE00C0).
   Упаковка — стандартная EFI (CompressionType=1, **Tiano/EFI 1.1**);
   распаковывает **серверный UEFI** при загрузке ROM (gEfiDecompressProtocol)
   — потому в плейнтексте флеша/BAR строк нет. sysfs-ром (§8) байт-в-байт =
   упакованная секция: «расшифровки при отдаче BAR» нет (гипотеза
   опровергнута).
2. **Строки generic-свойство драйвера, не HPE-билда**: распакованный img2
   HPE == generic CDA-4030 побайтно (у generic есть и ARM64-дубль img3,
   HPE-сборка без него); старый билд 14.28.15 (EX-дамп) содержит тот же
   набор строк. Драйвер пишет в ConOut **всегда, когда исполняется** —
   «печатают только HPE-карты» объясняется условиями исполнения, не ручкой:
   у 81:00.0 ROM-BAR сейчас отдаёт только img0+img1 (UEFI-драйвер не
   грузится — печатать некому; почему BAR обрезан — открытый вопрос), плюс
   маршрутизация консоли сервером. Ручки verbosity в конфиге FW карты
   **нет** (проверено: TLV FW_MAIN_CFG/ROM INI bitmap, журнал §6).
3. **`QueryClpCommands … Status = 14`** — тоже драйвер карты (HPE
   CLP-интерфейс внутри `Mlx5Nodnic`, строка `QueryClpCommands: Query
   failed(Status = %d)`); 14 = **EFI_NOT_FOUND** (базовый UEFI status code).
   Драйвер поднялся, но конфиг/данные не отдал — симптом битой прошивки
   (INI/NV), не отдельная поломка.
4. Точной строки «Checking cable» в драйвере нет; ближайшая —
   `netops_Init: Link is down(Cable not detected),Port = %d`.

### 11.1 Гейт печати — карточный NV-config (2026-10-01, реверс драйвера)

Журнал `superpowers/journal/2026-10-01-mlx5nodnic-print-gate-re.md`
(реверс `Mlx5Nodnic`, артефакт `refs/dumps/oprom-41-img2-unpacked-2026-10-01.bin`).

- Семейство «Mellanox Driver: …» (то, что на VGA/SOL) гейтится битом
  **`tech_enum` (bit 3) битмапы GLOBAL_ROM_INI** — NV-TLV `tlv_type 0x0100`
  (16 Б), читается через ICMD **MNVDA** (0x9024); битмап парсится только при
  bit31=`undi_en`=1. Вывод — сырой `gST->StdErr->OutputString` (не
  PrintLib/DEBUG). У HPE-карты `exprom_config.data[29]=0xCCE0180E` →
  bit3=1 → печать включена. Имя бита — по CX-3 debug-ini
  (`romini.tech_enum`); биекция 12 ручек ini ↔ биты `0xCCE0180E`.
- Второе семейство («MlxXxx: …», «UEFI Version», вход `QueryClpCommands`) —
  **NV-TLV `0x0206`** (4 Б BE): bits[1:0]=level, bits[7:4]=target
  (1=ConOut, 2=StdErr, 3=оба; CLP-ошибка гейтится только target).
  На битой CX-4: TLV 0x0206 прочитан (target≠0), но level≤1 и
  ROM-INI bit3=0 → видна только CLP-ошибка.
- UEFI-переменных verbosity драйвер не читает (всего две: `PlatformLang`,
  `EnclosureInformation`).
- **Практический вывод:** вкл/выкл POST-лога — это NV-настройка карты
  (запись TLV GLOBAL_ROM_INI bit3 / в образе — INI-битмапа), не серверная
  ручка. Прошивка HPE-образа в другую карту несёт bit3=1 → карта начнёт
  печатать (при условии, что отдаёт EFI-ROM, см. 11.2).
- **Локация в образе (2026-10-01):** это не TOC-секция, а TLV внутри INI:
  секция **FW_MAIN_CFG (0x12)**, блок `exprom_config`, TLV **`0x82000010`
  «ROM INI»** — в HPE-дампе @0x43e8d4 (hdr) / значение @0x43e8dc
  (`cc e0 18 0e`); в PRS-тексте — `exprom_config.data[29]=0xCCE0180E`
  (комментарий в dc прямо перечисляет 12 ручек, вкл. `tech_enum = 1`).
  `tech_enum` = **bit3** первого dword (0x0E=0b00001110). Выключение =
  0xCCE0180E→0xCCE01806 (+пересчёт CRC секции; подпись → FNP-путь).
- **Подтверждение наблюдением владельца (2026-10-01):** 42:00.0 (CX-4)
  печатает только CLP-ошибку (target≠0, bit3=0), на иных прошивках — ничего;
  «печатает только прошивка HPE». Разъяснилось: в CX-4-образе 12.28.4706
  блока `exprom_config`/TLV `0x82000010` в INI **нет вовсе** (`dc` не
  содержит) → ROM-INI не провижинится → драйвер читает дефолт (bit3=0).
- **Почему mstconfig этих битов не показывает (2026-10-01, SQLite-DB
  тула):** видимость задаёт `mlxconfig/mlxconfig_dbs/mlxconfig_host.db`
  (в refs/src/mstflint; таблицы `tlvs`/`params`) — параметр попадает в CLI
  только при непустом `params.mlxconfig_name`. Наш NV-TLV `0x0100` =
  **`nv_rom_ini`** (target `EXP_ROM`, size 16, TLV-имя «ROM INI») — все 33
  параметра (вкл. `tech_enum` @0x0.3, описание «Add technology enumeration
  to device name string») с `mlxconfig_name=NULL` → TLV целиком скрыт.
  Контраст: TLV `0x0206` = `nv_rom_uefi_debug_level` замаплен в публичные
  токены (`UEFI_LOGS`, `UEFI_LOG_VERBOSE`, `UEFI_LOG_MIN_SEVERITY`), TLV
  `0x0202` = `nv_rom_debug_level` → `BOOT_DBG_LOG_*` (FlexBoot). Всего в DB
  1552 параметра, CLI-имя у 815 → **737 скрытых (~47%)**. Т.е.
  «непубличная настройка» = есть в вендорской схеме (даже с описанием),
  но без публичного токена — крутится только патчем INI/NV.

### 11.2 ROM-обзор всех карт сервера (2026-10-01)

Журнал `superpowers/journal/2026-10-01-oprom-survey-all-cards.md`,
дампы `refs/dumps/oprom-survey-*-2026-10-01.bin`. EFI-суб-образ через
ROM-BAR отдают **2 из 5**: 41:00.0 (HPE) и **42:00.0 (CX-4, UEFI 14.21.21 —
драйвер с тем же набором POST-строк)**. Остальные (01:00.0, 81:00.0,
c1:00.0) цепочку обрывают после vendor-img1 (indicator=0x80) — UEFI-драйвер
не отдаётся вовсе, хотя трейлеры UEFI 14.29.15 во флеше есть (у 01:00.0
img1+трейлеры байт-в-байт как у HPE, отличие — 1 байт indicator).
Т.е. молчание трёх карт — структурное (нет EFI-ROM), печать 42:00.0 —
вопрос его NV-гейта (11.1): если по наблюдению владельца 42:00.0 молчит,
значит у него bit3=0 — финальное подтверждение механизма.
