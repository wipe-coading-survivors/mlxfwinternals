# 015. eth_speeds_supported: биты скоростей в FW_MAIN_CFG

> Источник: из 90 §4 (дополнительное независимое исследование, 2026-09-06;
> метод — эмпирика по образам `refs/fw/` через Python-пробники
> `scripts/probes/`; сверка PRS↔бинарный байт по трём картам). Перепроверено
> по исходнику 90 при переносе 2026-11-07.
> Связи: CRC-пересчёт секций ITOC → `../100-formats/025-crc.md`; PRS/секция
> 0x30 → `../100-formats/067-prs-zlib.md`; тип секции 0x12 и FS4-ядро →
> `../100-formats/030-fs4.md`; ini-маппинг →
> `docs/550-poc/100-mlxfwutil/010-ini-mapping.md`; инструмент патча
> `scripts/probes/patch_56g.py` →
> `docs/550-poc/100-mlxfwutil/040-probes-catalog.md`;
> чип→формат/скорости карт → `../100-formats/060-chip-map.md`.

TL;DR (из 90 §0.4): `eth_speeds_supported` (в т.ч. `Speed56Gb`) — в бинарной
секции `FW_MAIN_CFG` (`0x12`); битовая карта верифицирована по трём картам:
CX-5 100G (`0xbb`), CX-5 25G (`0x0b`), CX-4 56G (`0x5b`). Патч 56G = `| 0x40`.

## 1. Где поле

Поле `phy_fw_main_config.phy_shomron.lcl[x].eth_speeds_supported` (PRS
`[fw_main_config]`, «plastic fw config data») запекается в **бинарную секцию
FW_MAIN_CFG (тип `0x12`)**. Пер-порт байт (`lcl[0]`, `lcl[1]`) идёт парой со
стридом `0xC`.

## 2. Битовая карта (верифицирована)

Сравнение трёх образов с разными наборами скоростей (PRS → бинарный байт):

| Карта | PRS `lcl[0]` (1,10,25,40,50,56,100) | Бинарный байт | Поставленные биты |
|---|---|---|---|
| CX-5 100G (Dell 09FTMY = `CARD_DELL_CX5EX`, MCX516A-CDA и др.) | `1 1 1 1 1 0 1` | `0xbb` | 0,1,3,4,5,7 |
| CX-5 25G (MCX512A-ADA) | `1 1 1 0 0 0 0` | `0x0b` | 0,1,3 |
| CX-4 56G (MCX456A-FCA) | `1 1 0 1 1 1 0` (1,10,25,40,56) | `0x5b` | 0,1,3,4,6 |

Отсюда однозначная карта (CX-5; у CX-4 дополнительно `bit2=20G`):

```
bit0 = 1G     bit1 = 10G    bit2 = 20G (резерв, в CX-5 не используется)
bit3 = 25G    bit4 = 40G    bit5 = 50G
bit6 = 56G    bit7 = 100G
```

**Ключевое:** `Speed56Gb = bit6 = 0x40`. Доказательство — CX-4 56G-карта:
её `lcl`-байт `0x5b = bits{0,1,3,4,6}` = ровно набор {1G,10G,25G,40G,**56G**}.
(Консистентно с `../100-formats/060-chip-map.md`: MCX512A —
`Speed10/25Gb=1`, набор
{1G,10G,25G} = `0x0b`.)

## 3. Локация байта (сдвигается по версиям FW)

| Образ | `FW_MAIN_CFG` | `lcl[0]` rel / abs | `lcl[1]` rel / abs |
|---|---|---|---|
| Dell `16_27_6120` (09FTMY) | `@0x3c50b4` size `0xc00` | `0x30b` / `0x3c53bf` | `0x317` / `0x3c53cb` |
| stock `16_35_1012` (MCX516A/512A/545A/…) | `@0x439480` size `0xb00` | `0x2ab` | `0x2b7` |
| CX-4 `12_28_4706` (MCX456A) | `@0x14000` size `0xc00` | `0x30b` | `0x317` |

**Практическое правило (версионно-независимое):** в `FW_MAIN_CFG` искать
байт `0xbb` (стандартный 100G-набор) парой со стридом `0xC`; сверить с
PRS-набором скоростей; патчить `| 0x40`. Так делает
`scripts/probes/patch_56g.py` (каталог —
`docs/550-poc/100-mlxfwutil/040-probes-catalog.md`; для
Dell `16_27_6120` меняет ровно 6 байт: 2× lcl `0xbb→0xfb` + `sec_crc` +
`entry_crc` в записи ITOC; CRC-порядок — `../100-formats/025-crc.md`).

## 4. Ссылочная карта MCX516A-CDA (из 90 §4.4)

`refs/fw/cx-5-6/MCX516A-CDA_Ax_Bx-dc.ini` = **2-портовая Eth (EN, не VPI)
CX-5 Ex**: PRS `cx5_MCX516A_2p_x16_pci4.prs`, «ConnectX-5 Ex EN … 100GbE
dual-port QSFP28; PCIe4.0 x16». `Speed56Gb=0` (как у Dell), `lcl=0xbb`.
Использован как эталон «2p Eth Ex» для сверки локации/битов (совпадает с
Dell).
