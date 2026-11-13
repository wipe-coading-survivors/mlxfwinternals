# ConnectX-5 — карта SKU (OPN ↔ спецификация)

Дата: 2026-09-12. Источники: `refs/fw/cx-5-6/mellanox_connectx5_EN_models.csv`
+ `mellanox_connectx5_VPI_models.csv` (таблицы моделей Mellanox, дословно —
§1/§2), описания из `-dc.ini` / IMAGE_INFO (0x10) образов в refs (§4), PSID —
измерено `mstflint -i <img> q` (§4), OCP-статус — ini «for OCP» + поле
`HW_BOOT_CFG (0x08)+0x22` (0x03=OCP; docs/750-exp/120-eda-ib-node §4.8).

Цель: по любому образцу/OPN в refs видеть, какая это плата (порты/скорости/
PCIe/форм-фактор) и не перепутать std с OCP / чужой board-профиль с родным
(урок ch4: x8/OCP-профиль не грузится на нашей x16-карте; 2026-09-12:
родной для платы 8008 найден — MCX556A-ECA, §4/§5, docs/050-hardware/100-inventory).

## 1. EN-модели (CSV, дословно)

| Max Network Speed | Interface | Eth speeds (GbE) | Host Interface | Additional Features | OPN |
|---|---|---|---|---|---|
| 2x 25GbE | SFP28 | 25,10,1 | PCIe 3.0 x8 | | MCX512A-ACAT |
| 2x 25GbE | SFP28 | 25,10,1 | PCIe 3.0 x8 | UEFI Enabled (x86/Arm) | MCX512A-ACUT |
| 2x 25GbE | SFP28 | 25,10,1 | PCIe 4.0 x8 | ConnectX-5 Ex | MCX512A-ADAT |
| 2x 25GbE | SFP28 | 25,10,1 | PCIe 3.0 x16 | | MCX512F-ACAT |
| 2x 25GbE | SFP28 | 25,10,1 | PCIe 3.0 x16 | Enhanced Host Management | MCX512F-ACHT |
| 2x 40GbE | QSFP28 | 40,25,10,1 | PCIe 4.0 x16 | ConnectX-5 Ex | MCX516A-BDAT |
| 1x 50GbE | QSFP28 | 50,40,25,10,1 | PCIe 3.0 x16 | | MCX515A-GCAT |
| 2x 50GbE | QSFP28 | 50,40,25,10,1 | PCIe 3.0 x16 | | MCX516A-GCAT |
| 1x 100GbE | QSFP28 | 100,50,40,25,10,1 | PCIe 3.0 x16 | | MCX515A-CCAT |
| 1x 100GbE | QSFP28 | 100,50,40,25,10,1 | PCIe 3.0 x16 | UEFI Enabled (x86/Arm) | MCX515A-CCUT |
| 2x 100GbE | QSFP28 | 100,50,40,25,10,1 | PCIe 3.0 x16 | | MCX516A-CCAT |
| 2x 100GbE | QSFP28 | 100,50,40,25,10,1 | PCIe 3.0 x16 | Enhanced Host Management | MCX516A-CCHT |
| 2x 100GbE | QSFP28 | 100,50,40,25,10,1 | PCIe 4.0 x16 | ConnectX-5 Ex | MCX516A-CDAT |

## 2. VPI-модели (CSV, дословно)

Содержимое CSV **побайтово идентично EN-CSV** (тот же список OPN) — VPI
(EDR IB + 100GbE) и EN — одно и то же железо, различается только
firmware-набор возможностей. Таблица — та же, что в §1.

## 3. Правила именования OPN (наблюдения по CSV + refs)

- **CSV-OPN заканчиваются на `T`** (ACAT, ACUT, ADAT, …CDAT). Буквы до
  конца: 1-я — серия портов (`A`=2×25 SFP28 x8 / `B`=2×40 / `C`=100G /
  `G`=50G), 2-я — скорость/вариант, 3-я — фича (`A` базовый, `U` UEFI,
  `H` Enhanced Host Management, `D` Gen4/Ex).
- **OPN файла прошивки = CSV-OPN без `T`** + суффикс кронштейна `_Ax_Bx`:
  `MCX512A-ACAT`→`MCX512A-ACA_Ax_Bx`, `…-ADAT`→`…-ADA_Ax_Bx`,
  `MCX516A-CDAT`→`MCX516A-CDA_Ax_Bx` (проверено по 3 парам: спецификации
  совпадают).
- **`N`-суффикс (…AN) = OCP-вариант** (`EDAN`, `CDAN`, `BCAN` — ini «for
  OCP», 0x22=0x03). Но правило не универсально: `MCX545A/B-ECA` — тоже OCP
  без `N`. **Авторитетные источники OCP-статуса: ini «for OCP» / поле
  0x08+0x22** (docs/750-exp/120-eda-ib-node §4.8, docs/550-poc/100-mlxfwutil/020-patch-matrix.md).
- Серии **54x/55x отсутствуют в CSV** (CSV покрывает только 512/515/516);
  данные по ним — из ini (таблица §4).

**Статус: требует уточнения (2026-09-12).** Правила выше — наблюдения
(проверены по парам), а не официальный стандарт Mellanox; существует
неавторитетный источник, описывающий именование (и он не 100% точен).
Датасет владельца: OPN на стикере платы **`MCX556A-ECAT`** — здесь `T` =
**Tall bracket** (в ini образов 556A «tall bracket» — в описании, включая
`;;[PS_INFO]`-комментарий в шапке). То есть T-суффикс на стикере — тип
кронштейна, а «файл = CSV минус T» — отдельная конвенция CSV-серии (или
совпадение). **Авторитетная идентификация образа — PSID + device_id + ini
(0x10), не буквы OPN.**

## 4. Образы CX-5 в refs (кросс-таблица)

PSID — измерено `mstflint -i q`; описание — из `-dc.ini` или IMAGE_INFO (0x10);
«CSV-аналог» — вывод по §3 (≈ = приблизительное соответствие).

| rel | OPN (файл) | PSID | описание (ini/0x10) | CSV-аналог | OCP |
|---|---|---|---|---|---|
| 16.35.1012 | MCX512A-ADA_Ax_Bx | MT_0000000361 | Ex EN 2×25G SFP28, PCIe3/4 x8 | MCX512A-ADAT | нет |
| 16.35.8008 | MCX512A-ADA_Ax_Bx | MT_0000000361 | то же | MCX512A-ADAT | нет |
| 16.35.8008 | MCX512A-ACA_Ax_Bx | MT_0000000080 | EN 2×10/25G SFP28, PCIe3 x8, tall bracket | MCX512A-ACAT | нет |
| 16.35.8008 | MCX512F-ACA_Ax_Bx | MT_0000000183 | EN 2×25G SFP28, PCIe3 x16 | MCX512F-ACAT | нет |
| 16.35.1012 | MCX516A-CDA_Ax_Bx | MT_0000000013 | Ex EN 2×100G QSFP28, PCIe4 x16, tall bracket | MCX516A-CDAT | нет |
| 16.35.1012 | MCX545A-ECA_Ax_Bx | MT_0000000077 | VPI **for OCP** 1×100G QSFP28, PCIe3 x16, no bracket | ≈MCX515A-CCAT | **да** |
| 16.35.1012 | MCX545B-ECA_Ax_Bx | MT_0000000207 | VPI **for OCP** 1×100G + host mgmt, PCIe3 x16, 8mm heatsink | ≈MCX515A-CCAT/UT | **да** |
| 16.35.1012 | MCX546A-EDAN_Ax | MT_0000000135 | VPI **for OCP** 2×100G QSFP28, PCIe4 x16, no bracket | (нет в CSV) | **да** |
| 16.35.8008 | MCX546A-BCAN_Ax | MT_0000000069 | EN **for OCP** 2×40G, PCIe3 x16, no bracket | ≈MCX516A-BDAT | **да** |
| 16.35.8008 | MCX546A-CDAN_Ax | MT_0000000058 | Ex EN **for OCP** 2×100G QSFP28, PCIe4 x16, no bracket | ≈MCX516A-CDAT | **да** |
| 16.35.1012 | MCX556A-ECU_Ax_Bx | MT_0000000504 | VPI 2×100G QSFP28, PCIe3 x16, UEFI | (нет в CSV) | нет |
| 16.35.1012 | **MCX556A-ECA_Ax** | **MT_0000000008** | VPI 2×100G QSFP28, PCIe3 x16, tall bracket — **родной образ подопытной (стикер ECAT, docs/050-hardware/100-inventory)** | (нет в CSV) | нет (0x22=0x01) |
| 16.35.8008 | **MCX556A-ECA_Ax** | **MT_0000000008** | то же, 8008-код — **родной 8008 подопытной (docs/050-hardware/100-inventory; ch5-база)** | (нет в CSV) | нет (0x22=0x01) |
| 16.35.1012 | MCX556A-EDA_Ax_Bx | MT_0000000009 | Ex VPI 2×100G QSFP28, PCIe4 x16, tall bracket — кросс-флеш владельца на подопытную (docs/050-hardware/100-inventory) | (нет в CSV) | нет |
| 16.35.4030 | 872726-B21 (HP) | HPE0000000009 | HPE EDR/ETH 2-port 841QSFP28 | (branded) | — |
| 16.35.4030 | 4030_eda_ri.bin (ri подопытной) | MT_0000000009 | = MCX556A-EDA — **не заводской: кросс-флеш владельца** (docs/050-hardware/100-inventory) | (нет в CSV) | нет |
| 16.27.6120 | 09FTMY (Dell) | DEL0000000004 | Dell CX-5 Ex 2×100G QSFP | (branded) | — |

## 5. Практические выводы

- Для подопытной (стикер **MCX556A-ECAT**, плата ECA-T: Gen3 x16 std VPI —
  docs/050-hardware/100-inventory) **родные образы теперь в refs: MCX556A-ECA 1012 + 8008** (PSID 0008,
  0x22=0x01, без «for OCP»). Урок ch4 «все 8008-x16 в refs — OCP» — **больше
  не истина** (2026-09-12). Ch5: бёрн **8008-ECA** (родной профиль + 8008-код)
  — самый «нативный» эксперимент (docs/750-exp/120-eda-ib-node §4.9). В карте сейчас EDA 16.35.4030
  (кросс-флеш владельца; EDA = Gen4-близнец, PSID 0009).
- Семейство 556A (2×100G QSFP28 x16 std tall-bracket): **ECA** = Gen3 (PSID
  0008, device_id `0x1017` — live-измерение; `0x100f` — непроверенное
  ожидание, docs/750-exp/120-eda-ib-node §4.10) — подопытная; **ECU** = Gen3 + UEFI (PSID 0504);
  **EDA** = Gen4 «Ex» (PSID 0009, device_id 0x1019). OCP-близнецы — серия 546A
  (EDAN/CDAN/BCAN, PSID 0135/0058/0069); EN-вариант 556A в refs отсутствует
  (близжайший std-EN 2×100G Gen4 — MCX516A-CDA, PSID 0013).
- Branded-образы (Dell/HP) — PSID-префиксы DEL/HPE; по железу — те же платы.
