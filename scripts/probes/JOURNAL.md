# JOURNAL — апгрейд CX-4 на 4706 single-port (рабочий лог, не для коммита)

Цель: карта A (12.28.2302, single-port 0x1013, наша) → код C (12.28.4706, dual-port)
+ 56G. 14.32 Lx — отложен. Журнал значимых шагов: где что лежит, что сделано, что нет.

## Сервер / карта
- Хост: `root-mellanox` = реестр `HOST_MELLANOX_IP` (hostname — реестр `HOST_MELLANOX_HOSTNAME`).
- Наша карта: `0000:42:00.0`, MT27700 [15b3:1013], sub 0x0013, PSID MT_2180110032,
  **non-secure**, PCIe **Gen3 x16**. До флеша iface `enp66s0np0`; после — `enp66s0f0np0`
  (+ `enp66s0f1np1` = фантомный port2 — см. баг).
- mstflint 4.34.0 (host); MFT 4.36.0 в контейнере.
- Инструменты (тулбоксы):
  - IB: `ssh root-mellanox toolbox run -c t-adm ibstat`
  - mlxlink: `ssh root-mellanox toolbox run -c t-mlxflint mlxlink -d 42:00.0 -p 1`
  - mlxlink НЕТ в t-adm, нет в host PATH.
- **Все карты сервера воткнуты в один Mellanox SN-2700** (общий свитч, autoneg).
  Партнёры (для DAC-теста, линкуются в SN-2700): `81:00.0`=100G up (mlx5_2),
  `41:00.0`=56G up (mlx5_4), `01:00.0`/`c1:00.0`=25G. Far-end оптики 42:00.0 = порт SN-2700.

## Образы (md5)
| что | путь | md5 |
|---|---|---|
| A (base ref, 1p 2302) | `refs/fw/cx-4/fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-…102.bin` | `b37620c0…` |
| C (code, 2p 4706) | `refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-…103.bin` | `1289bec0…` |
| **v1** (flashed, dual-bug) | `/tmp/cx4_4706_singleport.bin` = server `/var/roothome/cx4_4706_singleport.bin` | `4baf54f16fbab520e52b6d567cedca61` |
| backup (2302 до флеша) | server `/var/roothome/cx4_backup_pre4706.bin` | `e84a4006…` |
| **v2** (full-config, **flashed+работает**) | `/tmp/cx4_4706_sp_v2.bin` = server `/var/roothome/cx4_4706_sp_v2.bin` | `9ac17476e5211541e4b92d8e35997a58` |

## Скрипты
- `scripts/probes/graft_4706.py` — сборщик. **v2: копирует ВСЕ config-секции A
  (0x08/0x09/0x11/0x12) + lcl[0]=0xfb (56G) + 0x10 sub/PSID ←A.** (запущен → v2 собран)
- `scripts/probes/toc_probe.py` — ITOC, `crc16_mlx`, `bits`, `SECT_NAMES`.
- `scripts/probes/patch_56g.py` — референс CRC-модели.
- `refs/src/mstflint/` — исходники mstflint (для анализа).

## Ключевые findings
1. **CRC-модель**: sec_crc=crc16(секция) в ITOC bits 208..223; entry_crc=crc16(rec[:28])
   в bits 240..255. poly 0x100B, init/XOR 0xFFFF.
2. **Burn: plain FAILS** «The Digest in the signature is wrong» = `FWCOMPS_MCC_ERR_REJECTED_DIGEST_ERR`
   — проверку делает **FW через MCC-регистр**. Обход: `mstflint … --no_fw_ctrl -y burn`
   → прямой путь во flash («Burning FW image without signatures» + «Restoring signature»).
   Авто-fallback в прямой путь — только Quantum2/BB (`fw_ops.cpp:1054`); **CX-4 — всегда MCC,
   если не `--no_fw_ctrl`**. (summary имел ошибку `-apc` — таких флагов нет.)
3. **BAГ v1**: точечные правки пропустили `0x11:0x035` (SKU 0x13/0x14, остался 0x14=dual)
   и др. → карта грузится **DUAL-port** (2 PCIe func 42:00.0/.1). Фантомный port2
   (42:00.1, нет backplane) → **FW health err `synd 0x7: irisc not responding`** →
   `ACCESS_REG(0x805) timeout` на 42:00.0 → ethtool/mlxlink **зависают**.
4. **Config diff A(1p)↔C(2p)** port-поля: `0x11:0x185`(1/2 num_ports), `0x10:0x21`(0x13/0x14 SKU),
   `0x11:0x35`(0x13/0x14 SKU) ← **пропущено в v1**, `0x12:0x2c4/2c5/2c7`, lcl `0x12:0x30b/0x317`.
   Отсюда решение: копировать ВСЕ config-секции A целиком (v2).
5. 56G — **только через autoneg** (`mlx5e_speed_validate: 56G link speed requires autoneg enabled`);
   `ethtool -s speed 56000 autoneg off` = Invalid argument. 100G fixed — принимается, но без партнёра
   линка нет. Свитч в autoneg → наш порт тоже autoneg on.

## Timeline (это сессия)
- [x] v1 собран, offline верифицирован (CRC 0, mstflint q: 4706/MT_218/x16).
- [x] docs: переписан `docs/850-howto/140-fw-upgrade.md` (4706 основной, 14.32 отложен §8); ссылки в 92/TODO.
- [x] Pre-flash: card 2302 x16 non-secure, линк 56G; backup `ri` → cx4_backup_pre4706.bin.
- [x] scp v1 → server. Burn#1 (plain) → FAIL (digest). Диагноз по source (MCC vs --no_fw_ctrl).
- [x] **Burn#2 `--no_fw_ctrl` → OK.** Reboot (~3 мин).
- [x] Verify: FW 4706, PSID MT_218, **x16 ✓**, но линк DOWN.
- [x] Оптика 100G SR4 в port1; «no partner». ibstat: 2 порта Down/Disabled. mlxlink: Polling/
  ETH_AN_FSM_ABILITY_DETECT, «Negotiation failure», Enabled 100G+56G.
- [x] Force-скорости: 100G fixed (нет линка), 56G fixed (Invalid). dmesg → **FW health err (dual-bug)**.
- [x] Config diff A↔C → нашёл пропущенные port-поля → решение full-config (v2).
- [x] graft_4706.py обновлён на v2 (full-section copy).
- [x] **v2 собран** `/tmp/cx4_4706_sp_v2.bin` = server `/var/roothome/cx4_4706_sp_v2.bin`
      (md5 `9ac17476e5211541e4b92d8e35997a58`). Verify: 0x08/0x09/0x11 == A (0 diffs),
      0x12 == A + lcl[0]=0xfb; num_ports=1, SKU=0x13, sub=0x13, PSID MT_218; mstflint q=4706.
- [x] Device деградировал после speed-thrash: 79 health/timeout, **mstflint q зависает**
      (flash/MCC недоступны) → шить рискованно.
- [x] Warm reboot → v1-FW **hang в «pre-initializing»** (>120s), `mlx5_init_one -110`,
      **нет netdev**, driver не биндится. Прямой flash read (`--no_fw_ctrl q`) тоже висит.
      Итог: v1 (dual) фактически unusable. ipmitool на сервере нет.
- [x] **COLD BOOT** (владелец от розетки) → v1 поднялся (2 порта, окно).
- [x] **burn v2** `--no_fw_ctrl -y burn`. 1-я попытка прервана на 74% (внутр. timeout 150s,
      flash-I/O медленный). 2-я (timeout 450s) — **OK**, "Restoring signature - OK".
- [x] Reboot (warm, 180s) → **v2 работает**:
      - lspci: **только 42:00.0** (нет 42:00.1) → single-port ✓
      - netdev `enp66s0np0`, **devlink running fw = 12.28.4706** ✓, stored=4706, PSID MT_218 ✓
      - PCIe **x16** ✓
      - **Link UP 100000 Mb/s (100G), autoneg, full** к SN-2700 ✓
      - health count **стабилен 38** (не растёт) — one-time boot-assert synd 0x1 (FW восстановился).
- [ ] **РАЗБОР boot-assert** (synd 0x1 / ext 0x8949, irisc 4): один раз при инициализации,
      FW recovered, линк up. Оценить: benign ли для 4706-кода (проверить на следующих reboot).
- [x] **Тест 56G на оптике**: `ethtool -s enp66s0np0 speed 56000 autoneg on` → **Link up 56000
      Mb/s** (dmesg Link up @745s). 56G через autoneg работает. Вернул на 100G (`speed 100000
      autoneg on`) → 100G up. FW 4706 running. **Оптика: 100G ✓ + 56G ✓.**
- [x] **DAC 56G**: Mellanox passive copper 1m, 56GigE, PN 670759-B22 (в SN-2700, autoneg).
      NOTE: с advertise=100G линк down ("Unsupported cable") — DAC 56G не поддерживает 100G.
      `ethtool -s enp66s0np0 speed 56000 autoneg on` → **Link up 56000 Mb/s** (@1332s). ✓
- [x] **DAC 100G**: QSFP-100G-CU1M 1m (в SN-2700, autoneg). `speed 100000 autoneg on`
      → **Link up 100000 Mb/s** (@1493s). ✓
- [x] **ВСЕ ТЕСТЫ ПРОЙДЕНЫ**: оптика 100G+56G, DAC 56G (670759-B22), DAC 100G (CU1M).
      Карта v2 (single-port 4706, x16) работает 56G и 100G по оптике и DAC.
- [x] Autoneg/перетыкивание: карта **default advertise = 100G** (как HPE); 56G —
      через `speed 56000 autoneg on`; `ethtool -s advertise <mask>` = **EOPNOTSUPP**
      (mlx5 single-speed только); re-neg от карты работает (свитч autoneg подстраивается).
- [x] **No-touch**: **FW персистит последнюю скорость через reboot** (не OS: NM/ifcfg
      пустые, device unmanaged). Fresh default (первый v2-boot, не трогал) = 100G.
      No-touch после reboot (last=56000) → оптика сама сошлась на 56G, без ethtool.
- [x] docs/850-howto/140-fw-upgrade (ИТОГ + §7 `--no_fw_ctrl` + **§10 тесты линков/no-touch**) + TODO (4706 DONE) обновлены.
- [ ] **Остаток**: разобрать one-time boot-assert `synd 0x1`/ext `0x8949`/irisc 4
      (benign?; health-buffer/dump при следующем reboot). `docs/850-howto/140-fw-upgrade` ИТОГ.

## Откат
non-secure. Бэкап: `/var/roothome/cx4_backup_pre4706.bin` (2302). FNP-рекавери примет любой образ.
`mstflint -d 42:00.0 -i cx4_backup_pre4706.bin --no_fw_ctrl -y burn` → reboot.
