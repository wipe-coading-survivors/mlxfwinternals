# 100. Dell-база: результаты фазы 1 (merge конфиг-секций, 2 варианта, бут)

> Статус: **стадия 0 выполнена (2026-09-08); стадия 1 — флеш выполнен, бут НЕ получен** (S1-new: no-boot, §2.2–§2.4). Карта заперта в FNP; восстановление 56G — владельцем (§2.4). Переработка фазы — `TODO.md`, раздел «Переработка фазы Dell-база». Аномалии плана — §3.
> Дизайн/протокол —
> `docs/superpowers/specs/2026-09-07-dell-base-vpi-build-design.md`.
> В `docs/` — только результаты; сюда записываются данные стадий 0–1
> (команды, офсеты, md5, выводы) по образцу `docs/750-exp/160-hpe-cx5-vpi-gen4-precheck` §10.

## 0. Итог

- **S1-new (canary): НЕТ бута.** Оба образа — dense-укладка (§2.1, md5 7f2adf2d…)
  и layout-preserving (R7/R8, md5 61dfbd39…) — не бутуются: после FNP-флеша +
  cold power cycle карта отсутствует в PCI / остаётся в FNP. Причина не
  подтверждена (нет ROM-кода) — кандидаты и состояние вопроса: §3.1.
- **S1-old: не проверен** (дерево решений спека §5: no-boot S1-new → recovery).
- **Итог по дереву решений (спека §5):** ветка «no-boot S1-new» → recovery
  (откат 56G) → root-cause (R7) → fix + rebuild + re-burn (R8) → **опять no-boot**
  → **застревание**: flash в A/B-состоянии (S1-new в слоте 0x800000, слот 0x0
  невалидирован, boot-addr → 0x0); все операции mstflint (q/burn) — «Bad CRC».
  Восстановление mstflint-ом невозможно (failsafe — Bad CRC; `--nofs` — align-fail;
  `--nofs --ignore_dev_data` — C++-assertion crash). **Перезапись 56G — владельцем
  вручную** (§2.4).
- **База для следующего скоупа:** карта в FNP, flash в смешанном A/B-состоянии
  (§2.4). Главный вывод: слепой побайтовый merge двух версий FW (16.35-база +
  16.27-конфиг) и сдвиг A/B boot-адреса — кандидаты на no-boot. Переработка фазы
  на более мелкие шаги — `TODO.md` → «Переработка фазы Dell-база» (обоснованный
  merge, §4).

## 1. Стадия 0 — офлайн-подготовка

### 1.1 ITOC/DTOC

`python3 mlxfwutil.py info <image>` (из корня репо, 2026-09-08):

- Dell 16.27.6120 (`09FTMY`): ITOC @ 0x4000 (25 записей), DTOC @ 0xfff000 (7 записей)
- HPE 16.35.4030 (`872726`): ITOC @ 0x5000 (25 записей), DTOC @ 0xfff000 (7 записей)
- CRC: все OK — `python3 mlxfwutil.py verify` по обоим образам:
  `RESULT: PASS (ITOC 25 + DTOC 7 sections, all CRC OK)`

Dell 16.27.6120 (`fw-ConnectX5-rel-16_27_6120-09FTMY_071C1T_Ax-UEFI-14.20.27-FlexBoot-3.5.903.signed.bin`):

```
== refs/fw/cx-5-6/fw-ConnectX5-rel-16_27_6120-09FTMY_071C1T_Ax-UEFI-14.20.27-FlexBoot-3.5.903.signed.bin (16777216 bytes)
  ITOC @ 0x4000: flash_layout_ver=1 ver=1 num_entries=0 hdr_crc=OK
    [ 0] 0x05 IRON_PREP_CODE   size=0x00010364 addr=0x000005000 sec_crc=0x2486(OK) entry_crc=0xcb5f(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 1] 0x20 RESET_INFO       size=0x00000100 addr=0x000015364 sec_crc=0x3d06(OK) entry_crc=0xe94d(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 2] 0x03 MAIN_CODE        size=0x0034dfc0 addr=0x000015464 sec_crc=0x716f(OK) entry_crc=0xc305(OK) z=0 cl=1 ver=0x000 enc=0 crcf=0
    [ 3] 0x04 PCIE_LINK_CODE   size=0x000140a4 addr=0x000363424 sec_crc=0x41e4(OK) entry_crc=0x0f1c(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 4] 0x06 POST_IRON_BOOT   size=0x00000b70 addr=0x0003774c8 sec_crc=0x1116(OK) entry_crc=0xcbbb(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 5] 0x02 PCI_CODE         size=0x0003fb78 addr=0x000378038 sec_crc=0x0646(OK) entry_crc=0xc572(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 6] 0x07 UPGRADE_CODE     size=0x00001964 addr=0x0003b7bb0 sec_crc=0x15b9(OK) entry_crc=0x0637(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 7] 0x0a PHY_UC_CODE      size=0x00009920 addr=0x0003b9514 sec_crc=0x90d1(OK) entry_crc=0xdc33(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 8] 0x0c PCIE_PHY_UC_CODE size=0x00001e80 addr=0x0003c2e34 sec_crc=0x4a42(OK) entry_crc=0xe111(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 9] 0x10 IMAGE_INFO       size=0x00000400 addr=0x0003c4cb4 sec_crc=0xf799(OK) entry_crc=0x06f6(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [10] 0x12 FW_MAIN_CFG      size=0x00000c00 addr=0x0003c50b4 sec_crc=0x319d(OK) entry_crc=0x3c1a(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [11] 0x11 FW_BOOT_CFG      size=0x00000400 addr=0x0003c5cb4 sec_crc=0x3a06(OK) entry_crc=0x646e(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [12] 0x09 HW_MAIN_CFG      size=0x00001580 addr=0x0003c60b4 sec_crc=0x951d(OK) entry_crc=0x4f32(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [13] 0x08 HW_BOOT_CFG      size=0x00000140 addr=0x0003c7634 sec_crc=0x3bd0(OK) entry_crc=0x3b0e(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [14] 0x0b PHY_UC_CONSTS    size=0x00002c80 addr=0x0003c7774 sec_crc=0x118d(OK) entry_crc=0x60e2(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [15] 0xa0 SIG_256          size=0x00000140 addr=0x0003ca3f4 sec_crc=0x0000(OK) entry_crc=0xadb7(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [16] 0xa1 PUB_KEYS_2048    size=0x00000900 addr=0x0003ca534 sec_crc=0xee35(OK) entry_crc=0x139d(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [17] 0xa2 FORBIDDEN_VER    size=0x00000090 addr=0x0003cae34 sec_crc=0x5540(OK) entry_crc=0x23bc(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [18] 0xa3 SIG_512          size=0x00000240 addr=0x0003caec4 sec_crc=0x0000(OK) entry_crc=0xdb66(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [19] 0xa4 PUB_KEYS_4096    size=0x00001100 addr=0x0003cb104 sec_crc=0x1da2(OK) entry_crc=0xa48c(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [20] 0x18 ROM_CODE         size=0x00064c28 addr=0x0003cc204 sec_crc=0xe0f9(OK) entry_crc=0xbfa7(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [21] 0x30 DBG_FW_INI       size=0x00000bf4 addr=0x000430e2c sec_crc=0x2814(OK) entry_crc=0xff98(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [22] 0x32 DBG_FW_PARAMS    size=0x00000008 addr=0x000431a20 sec_crc=0x7e05(OK) entry_crc=0xdb3c(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [23] 0xe9 CRDUMP_MASK      size=0x00010000 addr=0x000431a28 sec_crc=0x8370(OK) entry_crc=0x01b4(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [24] 0xeb PROG_HW_FW1      size=0x00050000 addr=0x000441a28 sec_crc=0x0f6f(OK) entry_crc=0x0fbc(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [25] END
  DTOC @ 0xfff000: flash_layout_ver=1 ver=1 num_entries=0 hdr_crc=OK
    [ 0] 0xe5 FW_NV_LOG        size=0x00010000 addr=0x000f90000 sec_crc=0x0000(OK) entry_crc=0xb075(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [ 1] 0xe6 NV_DATA0         size=0x00010000 addr=0x000fb0000 sec_crc=0x0000(OK) entry_crc=0x3651(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [ 2] 0xe4 NV_DATA2         size=0x00010000 addr=0x000fc0000 sec_crc=0x0000(OK) entry_crc=0x6917(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [ 3] 0xe1 DEV_INFO         size=0x00000200 addr=0x000fd0000 sec_crc=0x0000(OK) entry_crc=0xbc79(OK) z=0 cl=0 ver=0x000 enc=0 crcf=2
    [ 4] 0xe1 DEV_INFO         size=0x00000200 addr=0x000fe0000 sec_crc=0x0000(OK) entry_crc=0x5815(OK) z=0 cl=0 ver=0x000 enc=0 crcf=2
    [ 5] 0xe0 MFG_INFO         size=0x00000140 addr=0x000ff8000 sec_crc=0x8573(OK) entry_crc=0x8da9(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 6] 0xe3 VPD_R0           size=0x00000000 addr=0x000ff8140 sec_crc=0x0955(OK) entry_crc=0x3828(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 7] END
```

HPE 16.35.4030 (`fw-ConnectX5-rel-16_35_4030-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin`):

```
== refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin (16777216 bytes)
  ITOC @ 0x5000: flash_layout_ver=1 ver=1 num_entries=0 hdr_crc=OK
    [ 0] 0x05 IRON_PREP_CODE   size=0x00015614 addr=0x000007000 sec_crc=0xe007(OK) entry_crc=0xcb76(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 1] 0x20 RESET_INFO       size=0x00000100 addr=0x00001c614 sec_crc=0x3d06(OK) entry_crc=0xff1d(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 2] 0x03 MAIN_CODE        size=0x003d15a0 addr=0x00001c748 sec_crc=0x29fc(OK) entry_crc=0x7ebf(OK) z=0 cl=1 ver=0x000 enc=0 crcf=0
    [ 3] 0x04 PCIE_LINK_CODE   size=0x00013cd0 addr=0x0003edce8 sec_crc=0x2156(OK) entry_crc=0x8584(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 4] 0x06 POST_IRON_BOOT   size=0x00000b90 addr=0x0004019b8 sec_crc=0x7182(OK) entry_crc=0x0f27(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 5] 0x02 PCI_CODE         size=0x0002e140 addr=0x000402548 sec_crc=0xf440(OK) entry_crc=0x6449(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 6] 0x07 UPGRADE_CODE     size=0x00001ca0 addr=0x000430688 sec_crc=0x1dd7(OK) entry_crc=0x675a(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 7] 0x0a PHY_UC_CODE      size=0x00009920 addr=0x000432328 sec_crc=0x90d1(OK) entry_crc=0xc3d8(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 8] 0x0c PCIE_PHY_UC_CODE size=0x00001e80 addr=0x00043bc48 sec_crc=0x4a42(OK) entry_crc=0x2a1c(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 9] 0x10 IMAGE_INFO       size=0x00000400 addr=0x00043dac8 sec_crc=0xf394(OK) entry_crc=0x8d1e(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [10] 0x12 FW_MAIN_CFG      size=0x00000b00 addr=0x00043dec8 sec_crc=0x045a(OK) entry_crc=0x2ab1(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [11] 0x11 FW_BOOT_CFG      size=0x000004c0 addr=0x00043e9c8 sec_crc=0x3110(OK) entry_crc=0xc1af(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [12] 0x09 HW_MAIN_CFG      size=0x00000980 addr=0x00043ee88 sec_crc=0x57b8(OK) entry_crc=0x93ef(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [13] 0x08 HW_BOOT_CFG      size=0x00000140 addr=0x00043f808 sec_crc=0x61f7(OK) entry_crc=0x9819(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [14] 0x0b PHY_UC_CONSTS    size=0x00002c80 addr=0x00043f948 sec_crc=0x2743(OK) entry_crc=0xcf57(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [15] 0xa0 SIG_256          size=0x00000140 addr=0x0004425c8 sec_crc=0x0000(OK) entry_crc=0xf818(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [16] 0xa1 PUB_KEYS_2048    size=0x00000900 addr=0x000442708 sec_crc=0xee35(OK) entry_crc=0xb844(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [17] 0xa2 FORBIDDEN_VER    size=0x00000090 addr=0x000443008 sec_crc=0x5540(OK) entry_crc=0x5331(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [18] 0xa3 SIG_512          size=0x00000240 addr=0x000443098 sec_crc=0x0000(OK) entry_crc=0x90fe(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [19] 0xa4 PUB_KEYS_4096    size=0x00001100 addr=0x0004432d8 sec_crc=0x1da2(OK) entry_crc=0xd814(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [20] 0x18 ROM_CODE         size=0x0006fc28 addr=0x0004443d8 sec_crc=0x1ec5(OK) entry_crc=0xfe53(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [21] 0x30 DBG_FW_INI       size=0x00000d1c addr=0x0004b4000 sec_crc=0x7fdb(OK) entry_crc=0x5c1f(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [22] 0x32 DBG_FW_PARAMS    size=0x00000008 addr=0x0004b4d1c sec_crc=0x7e05(OK) entry_crc=0x06fd(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [23] 0xe9 CRDUMP_MASK      size=0x00008d30 addr=0x0004b4d24 sec_crc=0x6080(OK) entry_crc=0x85fb(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [24] 0xeb PROG_HW_FW1      size=0x00050000 addr=0x0004bda54 sec_crc=0x0f6f(OK) entry_crc=0xaa6e(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [25] END
  DTOC @ 0xfff000: flash_layout_ver=1 ver=1 num_entries=0 hdr_crc=OK
    [ 0] 0xe5 FW_NV_LOG        size=0x00010000 addr=0x000f90000 sec_crc=0x0000(OK) entry_crc=0xb075(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [ 1] 0xe6 NV_DATA0         size=0x00010000 addr=0x000fb0000 sec_crc=0x0000(OK) entry_crc=0x3651(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [ 2] 0xe4 NV_DATA2         size=0x00010000 addr=0x000fc0000 sec_crc=0x0000(OK) entry_crc=0x6917(OK) z=0 cl=0 ver=0x000 enc=0 crcf=1
    [ 3] 0xe1 DEV_INFO         size=0x00000200 addr=0x000fd0000 sec_crc=0x0000(OK) entry_crc=0xbc79(OK) z=0 cl=0 ver=0x000 enc=0 crcf=2
    [ 4] 0xe1 DEV_INFO         size=0x00000200 addr=0x000fe0000 sec_crc=0x0000(OK) entry_crc=0x5815(OK) z=0 cl=0 ver=0x000 enc=0 crcf=2
    [ 5] 0xe0 MFG_INFO         size=0x00000140 addr=0x000ff8000 sec_crc=0xd938(OK) entry_crc=0xe975(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 6] 0xe3 VPD_R0           size=0x00000000 addr=0x000ff8140 sec_crc=0x0955(OK) entry_crc=0x3828(OK) z=0 cl=0 ver=0x000 enc=0 crcf=0
    [ 7] END
```

### 1.2 PRS-сверка

`mlxfwutil.py extract <dell6120> -s 0x30` ↔ `refs/fw/cx-5-6/cx5-09FTMY_071C1T-dell-dc.ini`
(ожидаемо: побайтово, 16556 B, `docs/250-re/100-formats/067-prs-zlib.md`):

```
$ python3 mlxfwutil.py extract <dell6120> -s 0x30 -o /tmp/dell_prs.ini
/tmp/dell_prs.ini: 16556 bytes
$ cmp /tmp/dell_prs.ini refs/fw/cx-5-6/cx5-09FTMY_071C1T-dell-dc.ini
(без вывода) → **PRS: побайтово**, 16556 B — подтверждено (`docs/250-re/100-formats/067-prs-zlib.md`)
```

### 1.3 Таблица size по секциям (6120 vs 4030)

Скрипт стадии 0: обход ITOC/DTOC 6120, размер каждой секции в 4030 по
`(toc, index)`; все 32 записи (END не в счёт):

| Секция | size 6120 | size 4030 | размеры | Случай merge (спека §3) |
|---|---|---|---|---|
| ITOC 0x05 | 0x10364 | 0x15614 | размеры различаются | — |
| ITOC 0x20 | 0x100 | 0x100 | размеры равны | — |
| ITOC 0x03 | 0x34dfc0 | 0x3d15a0 | размеры различаются | — |
| ITOC 0x04 | 0x140a4 | 0x13cd0 | размеры различаются | — |
| ITOC 0x06 | 0xb70 | 0xb90 | размеры различаются | — |
| ITOC 0x02 | 0x3fb78 | 0x2e140 | размеры различаются | — |
| ITOC 0x07 | 0x1964 | 0x1ca0 | размеры различаются | — |
| ITOC 0x0a | 0x9920 | 0x9920 | размеры равны | — |
| ITOC 0x0c | 0x1e80 | 0x1e80 | размеры равны | — |
| ITOC 0x10 | 0x400 | 0x400 | размеры равны | merge полей (PSID/name/desc из Dell) |
| ITOC 0x12 | 0xc00 | 0xb00 | размеры различаются | база = 6120 (0xc00) |
| ITOC 0x11 | 0x400 | 0x4c0 | размеры различаются | база = 4030 (0x4c0) |
| ITOC 0x09 | 0x1580 | 0x980 | размеры различаются | база = 6120 (0x1580) |
| ITOC 0x08 | 0x140 | 0x140 | размеры равны | равные → дословно |
| ITOC 0x0b | 0x2c80 | 0x2c80 | размеры равны | — |
| ITOC 0xa0 | 0x140 | 0x140 | размеры равны | — |
| ITOC 0xa1 | 0x900 | 0x900 | размеры равны | — |
| ITOC 0xa2 | 0x90 | 0x90 | размеры равны | — |
| ITOC 0xa3 | 0x240 | 0x240 | размеры равны | — |
| ITOC 0xa4 | 0x1100 | 0x1100 | размеры равны | — |
| ITOC 0x18 | 0x64c28 | 0x6fc28 | размеры различаются | — |
| ITOC 0x30 | 0xbf4 | 0xd1c | размеры различаются | не merge (Dell-дословно) |
| ITOC 0x32 | 0x8 | 0x8 | размеры равны | — |
| ITOC 0xe9 | 0x10000 | 0x8d30 | размеры различаются | не merge (Dell-дословно) |
| ITOC 0xeb | 0x50000 | 0x50000 | размеры равны | не merge (Dell-дословно) |
| DTOC 0xe5 | 0x10000 | 0x10000 | размеры равны | не merge (4030-дословно; R8 — §2.4) |
| DTOC 0xe6 | 0x10000 | 0x10000 | размеры равны | не merge (4030-дословно; R8 — §2.4) |
| DTOC 0xe4 | 0x10000 | 0x10000 | размеры равны | не merge (4030-дословно; R8 — §2.4) |
| DTOC 0xe1 | 0x200 | 0x200 | размеры равны | не merge (4030-дословно; R8 — §2.4) |
| DTOC 0xe1 | 0x200 | 0x200 | размеры равны | не merge (4030-дословно; R8 — §2.4) |
| DTOC 0xe0 | 0x140 | 0x140 | размеры равны | не merge (4030-дословно; R8 — §2.4) |
| DTOC 0xe3 | 0x0 | 0x0 | размеры равны | не merge (4030-дословно; R8 — §2.4) |

### 1.4 Delta-таблица конфиг-секций (6120 ↔ 4030)

`python3 mlxfwutil.py diff <dell6120> <hpe4030> --max-ranges 64` — полный вывод
(A = 6120 Dell, B = 4030 HPE):

```
== diff: A=refs/fw/cx-5-6/fw-ConnectX5-rel-16_27_6120-09FTMY_071C1T_Ax-UEFI-14.20.27-FlexBoot-3.5.903.signed.bin  B=refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin
  [ITOC[0]] 0x05 IRON_PREP_CODE   SIZE 0x10364 vs 0x15614; 61212 diff bytes in overlap
      @0x000b..0x000b (1 B)
      @0x000e..0x0035 (40 B)
      @0x0037..0x0039 (3 B)
      @0x003b..0x003d (3 B)
      @0x003f..0x0045 (7 B)
      @0x0047..0x0049 (3 B)
      @0x004b..0x004b (1 B)
      @0x004d..0x0051 (5 B)
      @0x0053..0x0055 (3 B)
      @0x0057..0x0058 (2 B)
      @0x005a..0x005d (4 B)
      @0x005f..0x006d (15 B)
      @0x006f..0x0071 (3 B)
      @0x0073..0x0074 (2 B)
      @0x0076..0x007a (5 B)
      @0x007c..0x008a (15 B)
      @0x008c..0x0095 (10 B)
      @0x0097..0x009d (7 B)
      @0x009f..0x00a5 (7 B)
      @0x00a7..0x00ac (6 B)
      @0x00ae..0x00b1 (4 B)
      @0x00b3..0x00cb (25 B)
      @0x00cd..0x00cd (1 B)
      @0x00d0..0x00d9 (10 B)
      @0x00db..0x00dd (3 B)
      @0x00df..0x00e9 (11 B)
      @0x00eb..0x00ed (3 B)
      @0x00f0..0x00f5 (6 B)
      @0x00f7..0x0112 (28 B)
      @0x0114..0x0117 (4 B)
      @0x0119..0x011d (5 B)
      @0x011f..0x011f (1 B)
      @0x0121..0x0121 (1 B)
      @0x0123..0x0129 (7 B)
      @0x012b..0x012d (3 B)
      @0x012f..0x0133 (5 B)
      @0x0136..0x0155 (32 B)
      @0x0157..0x0171 (27 B)
      @0x0174..0x0179 (6 B)
      @0x017b..0x017d (3 B)
      @0x017f..0x0185 (7 B)
      @0x0187..0x01a2 (28 B)
      @0x01a4..0x01a5 (2 B)
      @0x01a7..0x01ad (7 B)
      @0x01af..0x01af (1 B)
      @0x01b1..0x01b1 (1 B)
      @0x01b3..0x01b9 (7 B)
      @0x01bb..0x01c1 (7 B)
      @0x01c3..0x01e2 (32 B)
      @0x01e4..0x01fe (27 B)
      @0x0200..0x0209 (10 B)
      @0x020b..0x020c (2 B)
      @0x020e..0x021d (16 B)
      @0x021f..0x021f (1 B)
      @0x0221..0x0234 (20 B)
      @0x0236..0x0249 (20 B)
      @0x024b..0x024d (3 B)
      @0x024f..0x0261 (19 B)
      @0x0263..0x0263 (1 B)
      @0x0268..0x0269 (2 B)
      @0x026b..0x0270 (6 B)
      @0x0273..0x027f (13 B)
      @0x0281..0x0295 (21 B)
      @0x0297..0x029d (7 B)
  [ITOC[1]] 0x20 RESET_INFO       identical (0x100)
  [ITOC[2]] 0x03 MAIN_CODE        SIZE 0x34dfc0 vs 0x3d15a0; 3103161 diff bytes in overlap
      @0x0000..0x001b (28 B)
      @0x001d..0x0021 (5 B)
      @0x0023..0x0035 (19 B)
      @0x0037..0x003f (9 B)
      @0x0042..0x005a (25 B)
      @0x005c..0x0060 (5 B)
      @0x0062..0x0066 (5 B)
      @0x0068..0x0069 (2 B)
      @0x006b..0x0079 (15 B)
      @0x007b..0x0081 (7 B)
      @0x0083..0x0083 (1 B)
      @0x0086..0x0089 (4 B)
      @0x008b..0x009b (17 B)
      @0x009d..0x00a5 (9 B)
      @0x00a7..0x00b1 (11 B)
      @0x00b3..0x00c1 (15 B)
      @0x00c3..0x00c5 (3 B)
      @0x00c7..0x00c7 (1 B)
      @0x00ca..0x00d1 (8 B)
      @0x00d3..0x0103 (49 B)
      @0x0105..0x010b (7 B)
      @0x010e..0x010f (2 B)
      @0x0111..0x0133 (35 B)
      @0x0135..0x0135 (1 B)
      @0x0137..0x013d (7 B)
      @0x013f..0x013f (1 B)
      @0x0141..0x014f (15 B)
      @0x0152..0x0156 (5 B)
      @0x0158..0x0175 (30 B)
      @0x0177..0x0177 (1 B)
      @0x017a..0x0181 (8 B)
      @0x0183..0x0185 (3 B)
      @0x0187..0x0189 (3 B)
      @0x018b..0x0193 (9 B)
      @0x0196..0x0197 (2 B)
      @0x0199..0x0199 (1 B)
      @0x019b..0x019b (1 B)
      @0x019d..0x019d (1 B)
      @0x01a0..0x01a1 (2 B)
      @0x01a3..0x01b5 (19 B)
      @0x01b7..0x01d3 (29 B)
      @0x01d5..0x01d5 (1 B)
      @0x01d7..0x01d7 (1 B)
      @0x01da..0x01dd (4 B)
      @0x01df..0x01ea (12 B)
      @0x01ec..0x01f1 (6 B)
      @0x01f3..0x01f5 (3 B)
      @0x01f7..0x0208 (18 B)
      @0x020a..0x020d (4 B)
      @0x020f..0x021b (13 B)
      @0x021e..0x0234 (23 B)
      @0x0236..0x0239 (4 B)
      @0x023b..0x0252 (24 B)
      @0x0254..0x025f (12 B)
      @0x0262..0x0265 (4 B)
      @0x0267..0x027d (23 B)
      @0x027f..0x0285 (7 B)
      @0x0287..0x0289 (3 B)
      @0x028b..0x02a3 (25 B)
      @0x02a6..0x02aa (5 B)
      @0x02ac..0x02b7 (12 B)
      @0x02b9..0x02d9 (33 B)
      @0x02db..0x02e7 (13 B)
      @0x02ea..0x02f9 (16 B)
  [ITOC[3]] 0x04 PCIE_LINK_CODE   SIZE 0x140a4 vs 0x13cd0; 70758 diff bytes in overlap
      @0x0c67..0x0c67 (1 B)
      @0x0c79..0x0c7f (7 B)
      @0x0c81..0x0ca6 (38 B)
      @0x0ca8..0x0ce1 (58 B)
      @0x0ce3..0x0cfa (24 B)
      @0x0cfc..0x0d05 (10 B)
      @0x0d07..0x0d11 (11 B)
      @0x0d13..0x0d16 (4 B)
      @0x0d18..0x0d31 (26 B)
      @0x0d33..0x0d3b (9 B)
      @0x0d3d..0x0d3d (1 B)
      @0x0d3f..0x0d3f (1 B)
      @0x0d41..0x0d46 (6 B)
      @0x0d49..0x0d51 (9 B)
      @0x0d53..0x0d55 (3 B)
      @0x0d57..0x0d83 (45 B)
      @0x0d85..0x0d85 (1 B)
      @0x0d8a..0x0d8a (1 B)
      @0x0d8c..0x0d8c (1 B)
      @0x0d8e..0x0db5 (40 B)
      @0x0db7..0x0dc1 (11 B)
      @0x0dc3..0x0dc5 (3 B)
      @0x0dc7..0x0ddd (23 B)
      @0x0ddf..0x0df5 (23 B)
      @0x0df7..0x0e11 (27 B)
      @0x0e13..0x0e1d (11 B)
      @0x0e1f..0x0e21 (3 B)
      @0x0e23..0x0e2f (13 B)
      @0x0e31..0x0e41 (17 B)
      @0x0e43..0x0e5d (27 B)
      @0x0e5f..0x0e69 (11 B)
      @0x0e6b..0x0e6c (2 B)
      @0x0e6e..0x0e71 (4 B)
      @0x0e73..0x0e7d (11 B)
      @0x0e7f..0x0e89 (11 B)
      @0x0e8b..0x0e9c (18 B)
      @0x0e9e..0x0ea8 (11 B)
      @0x0eaa..0x0eb0 (7 B)
      @0x0eb2..0x0eb7 (6 B)
      @0x0eb9..0x0eb9 (1 B)
      @0x0ebb..0x0ebd (3 B)
      @0x0ebf..0x0ec5 (7 B)
      @0x0ec7..0x0ecb (5 B)
      @0x0ecd..0x0ed5 (9 B)
      @0x0ed7..0x0ed7 (1 B)
      @0x0ed9..0x0edd (5 B)
      @0x0edf..0x0efd (31 B)
      @0x0eff..0x0f11 (19 B)
      @0x0f13..0x0f2d (27 B)
      @0x0f2f..0x0f30 (2 B)
      @0x0f32..0x0f37 (6 B)
      @0x0f39..0x0f39 (1 B)
      @0x0f3c..0x0f4c (17 B)
      @0x0f4e..0x0f50 (3 B)
      @0x0f52..0x0f60 (15 B)
      @0x0f62..0x0f64 (3 B)
      @0x0f66..0x0f74 (15 B)
      @0x0f76..0x0f78 (3 B)
      @0x0f7a..0x0f88 (15 B)
      @0x0f8a..0x0f8c (3 B)
      @0x0f8e..0x0f9c (15 B)
      @0x0f9e..0x0fa0 (3 B)
      @0x0fa2..0x0fb0 (15 B)
      @0x0fb2..0x0fb4 (3 B)
  [ITOC[4]] 0x06 POST_IRON_BOOT   SIZE 0xb70 vs 0xb90; 2604 diff bytes in overlap
      @0x0020..0x0022 (3 B)
      @0x0024..0x0025 (2 B)
      @0x0027..0x002d (7 B)
      @0x0030..0x003f (16 B)
      @0x0041..0x0049 (9 B)
      @0x004b..0x004d (3 B)
      @0x004f..0x0051 (3 B)
      @0x0053..0x0055 (3 B)
      @0x0057..0x0061 (11 B)
      @0x0063..0x007e (28 B)
      @0x0080..0x009d (30 B)
      @0x009f..0x00a0 (2 B)
      @0x00a3..0x00a9 (7 B)
      @0x00ab..0x00b1 (7 B)
      @0x00b3..0x00d6 (36 B)
      @0x00d8..0x00ed (22 B)
      @0x00ef..0x00f1 (3 B)
      @0x00f3..0x0121 (47 B)
      @0x0123..0x0125 (3 B)
      @0x0127..0x012d (7 B)
      @0x012f..0x012f (1 B)
      @0x0131..0x013d (13 B)
      @0x013f..0x0159 (27 B)
      @0x015b..0x0163 (9 B)
      @0x0166..0x0166 (1 B)
      @0x0168..0x0169 (2 B)
      @0x016c..0x016d (2 B)
      @0x0174..0x0175 (2 B)
      @0x017c..0x017d (2 B)
      @0x0180..0x0180 (1 B)
      @0x0185..0x0187 (3 B)
      @0x0189..0x0189 (1 B)
      @0x018c..0x018d (2 B)
      @0x0191..0x0191 (1 B)
      @0x0193..0x0197 (5 B)
      @0x0199..0x01a3 (11 B)
      @0x01a5..0x01a5 (1 B)
      @0x01a7..0x01a9 (3 B)
      @0x01ab..0x01b4 (10 B)
      @0x01b7..0x01c3 (13 B)
      @0x01c5..0x01c5 (1 B)
      @0x01c7..0x01c9 (3 B)
      @0x01cb..0x01d5 (11 B)
      @0x01d7..0x01e5 (15 B)
      @0x01e7..0x01e9 (3 B)
      @0x01eb..0x01f5 (11 B)
      @0x01f7..0x0205 (15 B)
      @0x0207..0x0209 (3 B)
      @0x020b..0x020d (3 B)
      @0x020f..0x021b (13 B)
      @0x021d..0x0229 (13 B)
      @0x022b..0x0233 (9 B)
      @0x0235..0x0242 (14 B)
      @0x0244..0x0244 (1 B)
      @0x0246..0x024b (6 B)
      @0x024d..0x0255 (9 B)
      @0x0257..0x0261 (11 B)
      @0x0263..0x0265 (3 B)
      @0x0267..0x0269 (3 B)
      @0x026b..0x026d (3 B)
      @0x026f..0x0292 (36 B)
      @0x0294..0x029e (11 B)
      @0x02a0..0x02ae (15 B)
      @0x02b0..0x02bb (12 B)
  [ITOC[5]] 0x02 PCI_CODE         SIZE 0x3fb78 vs 0x2e140; 185163 diff bytes in overlap
      @0x0000..0x000f (16 B)
      @0x0012..0x0012 (1 B)
      @0x0014..0x0055 (66 B)
      @0x0057..0x0079 (35 B)
      @0x007b..0x0095 (27 B)
      @0x0097..0x00b9 (35 B)
      @0x00bb..0x010b (81 B)
      @0x010d..0x010f (3 B)
      @0x0111..0x011b (11 B)
      @0x011d..0x0134 (24 B)
      @0x0136..0x013c (7 B)
      @0x013e..0x0177 (58 B)
      @0x0179..0x0185 (13 B)
      @0x0187..0x020e (136 B)
      @0x0210..0x0218 (9 B)
      @0x021a..0x021e (5 B)
      @0x0220..0x0231 (18 B)
      @0x0233..0x0233 (1 B)
      @0x0235..0x0235 (1 B)
      @0x0237..0x0239 (3 B)
      @0x023b..0x023c (2 B)
      @0x023e..0x024b (14 B)
      @0x024d..0x024f (3 B)
      @0x0251..0x025f (15 B)
      @0x0261..0x0261 (1 B)
      @0x0263..0x0271 (15 B)
      @0x0273..0x0273 (1 B)
      @0x0275..0x027d (9 B)
      @0x027f..0x0281 (3 B)
      @0x0283..0x0284 (2 B)
      @0x0287..0x02a1 (27 B)
      @0x02a3..0x02ad (11 B)
      @0x02af..0x02b9 (11 B)
      @0x02bb..0x02bc (2 B)
      @0x02be..0x02bf (2 B)
      @0x02c1..0x02d7 (23 B)
      @0x02d9..0x02e6 (14 B)
      @0x02e8..0x02f1 (10 B)
      @0x02f3..0x033d (75 B)
      @0x033f..0x0341 (3 B)
      @0x0343..0x0352 (16 B)
      @0x0355..0x0365 (17 B)
      @0x0367..0x03e1 (123 B)
      @0x03e3..0x03f1 (15 B)
      @0x03f3..0x03fe (12 B)
      @0x0400..0x0436 (55 B)
      @0x0438..0x045d (38 B)
      @0x045f..0x0487 (41 B)
      @0x0489..0x04af (39 B)
      @0x04b1..0x04b2 (2 B)
      @0x04b4..0x04b9 (6 B)
      @0x04bb..0x0541 (135 B)
      @0x0543..0x0546 (4 B)
      @0x0548..0x0569 (34 B)
      @0x056b..0x0574 (10 B)
      @0x0576..0x05be (73 B)
      @0x05c0..0x05d9 (26 B)
      @0x05db..0x05e7 (13 B)
      @0x05e9..0x0625 (61 B)
      @0x0627..0x063e (24 B)
      @0x0640..0x064d (14 B)
      @0x064f..0x0651 (3 B)
      @0x0653..0x065d (11 B)
      @0x065f..0x0665 (7 B)
  [ITOC[6]] 0x07 UPGRADE_CODE     SIZE 0x1964 vs 0x1ca0; 5592 diff bytes in overlap
      @0x0076..0x0077 (2 B)
      @0x009f..0x009f (1 B)
      @0x00b7..0x00b7 (1 B)
      @0x00c6..0x00c7 (2 B)
      @0x00ce..0x00cf (2 B)
      @0x00e3..0x00e3 (1 B)
      @0x010e..0x010f (2 B)
      @0x011a..0x011b (2 B)
      @0x0126..0x0127 (2 B)
      @0x0136..0x0137 (2 B)
      @0x013e..0x013f (2 B)
      @0x0146..0x0147 (2 B)
      @0x014e..0x014f (2 B)
      @0x0156..0x0157 (2 B)
      @0x015e..0x015f (2 B)
      @0x0166..0x0167 (2 B)
      @0x018d..0x018d (1 B)
      @0x0191..0x0191 (1 B)
      @0x0199..0x0199 (1 B)
      @0x019d..0x019d (1 B)
      @0x01a1..0x01a1 (1 B)
      @0x01a6..0x01a6 (1 B)
      @0x01a8..0x01a9 (2 B)
      @0x01ab..0x01cf (37 B)
      @0x01d2..0x01ef (30 B)
      @0x01f1..0x020f (31 B)
      @0x0211..0x022d (29 B)
      @0x022f..0x023d (15 B)
      @0x023f..0x026b (45 B)
      @0x026e..0x026e (1 B)
      @0x0270..0x0279 (10 B)
      @0x027b..0x0289 (15 B)
      @0x028b..0x02a9 (31 B)
      @0x02ab..0x02ad (3 B)
      @0x02af..0x02b1 (3 B)
      @0x02b3..0x02c1 (15 B)
      @0x02c3..0x02cf (13 B)
      @0x02d1..0x02f2 (34 B)
      @0x02f4..0x02f5 (2 B)
      @0x02f7..0x031a (36 B)
      @0x031c..0x0326 (11 B)
      @0x0328..0x0329 (2 B)
      @0x032b..0x032d (3 B)
      @0x032f..0x035e (48 B)
      @0x0360..0x0361 (2 B)
      @0x0363..0x0365 (3 B)
      @0x0367..0x0369 (3 B)
      @0x036b..0x0371 (7 B)
      @0x0373..0x0375 (3 B)
      @0x0377..0x037d (7 B)
      @0x037f..0x0381 (3 B)
      @0x0383..0x039d (27 B)
      @0x039f..0x03a6 (8 B)
      @0x03a8..0x03bd (22 B)
      @0x03bf..0x03c1 (3 B)
      @0x03c3..0x03c5 (3 B)
      @0x03c7..0x03d1 (11 B)
      @0x03d3..0x03d5 (3 B)
      @0x03d7..0x03d9 (3 B)
      @0x03db..0x03f9 (31 B)
      @0x03fb..0x0409 (15 B)
      @0x040b..0x040d (3 B)
      @0x040f..0x0415 (7 B)
      @0x0417..0x0419 (3 B)
  [ITOC[7]] 0x0a PHY_UC_CODE      identical (0x9920)
  [ITOC[8]] 0x0c PCIE_PHY_UC_CODE identical (0x1e80)
  [ITOC[9]] 0x10 IMAGE_INFO       141 diff bytes, 31 ranges
      @0x0003..0x0003 (1 B)
      @0x0009..0x000e (6 B)
      @0x0011..0x0013 (3 B)
      @0x001d..0x001d (1 B)
      @0x0020..0x0021 (2 B)
      @0x0023..0x0026 (4 B)  <- IMAGE_INFO+0x24 psid[17]
      @0x0030..0x0030 (1 B)
      @0x0110..0x0110 (1 B)
      @0x012d..0x012f (3 B)
      @0x0196..0x0197 (2 B)
      @0x019a..0x019b (2 B)
      @0x019e..0x019f (2 B)
      @0x01a2..0x01a3 (2 B)
      @0x01a6..0x01a7 (2 B)
      @0x01aa..0x01ab (2 B)
      @0x01ae..0x01af (2 B)
      @0x01b2..0x01b3 (2 B)
      @0x01b6..0x01b7 (2 B)
      @0x01ba..0x01bb (2 B)
      @0x01be..0x01bf (2 B)
      @0x01c7..0x01c8 (2 B)
      @0x01ca..0x01cc (3 B)
      @0x01d0..0x01d4 (5 B)  <- IMAGE_INFO+0x1d0 description[257]
      @0x01d6..0x01db (6 B)
      @0x01dd..0x01ea (14 B)
      @0x01ec..0x01f7 (12 B)
      @0x01f9..0x020c (20 B)
      @0x0340..0x0348 (9 B)  <- IMAGE_INFO+0x340 name[65]
      @0x034a..0x034c (3 B)
      @0x034e..0x034e (1 B)
      @0x0384..0x0399 (22 B)
  [ITOC[10]] 0x12 FW_MAIN_CFG      SIZE 0xc00 vs 0xb00; 1300 diff bytes in overlap
      @0x000c..0x000c (1 B)
      @0x000f..0x000f (1 B)
      @0x0012..0x0012 (1 B)
      @0x0017..0x001b (5 B)
      @0x0023..0x0023 (1 B)
      @0x004c..0x004c (1 B)
      @0x0071..0x0073 (3 B)
      @0x0076..0x0077 (2 B)
      @0x007a..0x007b (2 B)
      @0x007e..0x007f (2 B)
      @0x00a0..0x00a2 (3 B)
      @0x00a5..0x00a6 (2 B)
      @0x00a9..0x00ab (3 B)
      @0x00ad..0x00ae (2 B)
      @0x00b1..0x00b3 (3 B)
      @0x00b5..0x00b6 (2 B)
      @0x00b9..0x00bc (4 B)
      @0x00c6..0x00c7 (2 B)
      @0x00e3..0x00e3 (1 B)
      @0x00ec..0x00fb (16 B)
      @0x0100..0x0102 (3 B)
      @0x0105..0x0106 (2 B)
      @0x0109..0x0113 (11 B)
      @0x0115..0x0116 (2 B)
      @0x0119..0x011c (4 B)
      @0x0126..0x0127 (2 B)
      @0x0143..0x0143 (1 B)
      @0x014c..0x015b (16 B)
      @0x0168..0x0171 (10 B)
      @0x01a0..0x01a0 (1 B)
      @0x01a3..0x01a3 (1 B)
      @0x01a6..0x01a7 (2 B)
      @0x01ab..0x01ab (1 B)
      @0x01ad..0x01af (3 B)
      @0x01bb..0x01bb (1 B)
      @0x01c5..0x01cd (9 B)
      @0x0200..0x0200 (1 B)
      @0x0203..0x0203 (1 B)
      @0x0223..0x0223 (1 B)
      @0x0227..0x0227 (1 B)
      @0x022b..0x022b (1 B)
      @0x0233..0x0233 (1 B)
      @0x0237..0x0237 (1 B)
      @0x023b..0x023b (1 B)
      @0x023f..0x023f (1 B)
      @0x0243..0x0243 (1 B)
      @0x024b..0x024b (1 B)
      @0x024f..0x024f (1 B)
      @0x0253..0x0253 (1 B)
      @0x0257..0x0257 (1 B)
      @0x025b..0x025b (1 B)
      @0x025f..0x025f (1 B)
      @0x0262..0x0267 (6 B)
      @0x0271..0x0273 (3 B)
      @0x027b..0x027b (1 B)
      @0x027d..0x027d (1 B)
      @0x0281..0x0281 (1 B)
      @0x0283..0x0283 (1 B)
      @0x0287..0x0287 (1 B)
      @0x0293..0x0293 (1 B)
      @0x0297..0x0297 (1 B)
      @0x029b..0x029b (1 B)
      @0x029f..0x02a0 (2 B)
      @0x02a2..0x02a3 (2 B)
  [ITOC[11]] 0x11 FW_BOOT_CFG      SIZE 0x400 vs 0x4c0; 298 diff bytes in overlap
      @0x0005..0x000a (6 B)
      @0x000d..0x000f (3 B)
      @0x0011..0x0011 (1 B)
      @0x0019..0x001c (4 B)
      @0x0028..0x002f (8 B)  <- FW_BOOT_CFG+0x2d device_id low byte |0x1000 (16.35 layout)
      @0x0031..0x0033 (3 B)
      @0x0035..0x0037 (3 B)
      @0x003a..0x0040 (7 B)  <- FW_BOOT_CFG+0x3d subsystem_id low byte
      @0x0042..0x0043 (2 B)
      @0x0045..0x0047 (3 B)
      @0x0049..0x004c (4 B)
      @0x004e..0x004f (2 B)
      @0x0051..0x0053 (3 B)
      @0x0055..0x0057 (3 B)
      @0x005b..0x005b (1 B)
      @0x0062..0x0063 (2 B)
      @0x006a..0x006a (1 B)
      @0x006e..0x006e (1 B)
      @0x0073..0x0073 (1 B)
      @0x0075..0x0077 (3 B)
      @0x007a..0x007f (6 B)
      @0x0082..0x0082 (1 B)
      @0x0087..0x0087 (1 B)
      @0x0089..0x008b (3 B)
      @0x008e..0x008f (2 B)
      @0x0091..0x0093 (3 B)  <- FW_BOOT_CFG+0x93 PCIe cap_index (0x45=Gen3, 0x47=Gen4)
      @0x0099..0x009a (2 B)
      @0x009c..0x00bb (32 B)
      @0x00d4..0x00d7 (4 B)
      @0x00dc..0x00dc (1 B)
      @0x00de..0x00e7 (10 B)
      @0x0100..0x0121 (34 B)
      @0x0123..0x0127 (5 B)
      @0x012c..0x012e (3 B)
      @0x0130..0x0131 (2 B)
      @0x0133..0x013b (9 B)
      @0x0140..0x0140 (1 B)
      @0x0142..0x014b (10 B)
      @0x01a4..0x01a4 (1 B)
      @0x01ac..0x01ac (1 B)
      @0x01dd..0x01df (3 B)
      @0x01f0..0x01f0 (1 B)
      @0x0200..0x0200 (1 B)
      @0x0204..0x0205 (2 B)
      @0x0207..0x020b (5 B)
      @0x0210..0x0211 (2 B)
      @0x0213..0x0215 (3 B)
      @0x0217..0x021b (5 B)
      @0x021e..0x021f (2 B)
      @0x0228..0x022b (4 B)
      @0x022d..0x022e (2 B)
      @0x0258..0x025b (4 B)
      @0x025d..0x025e (2 B)
      @0x0288..0x028e (7 B)
      @0x0290..0x0290 (1 B)
      @0x02b7..0x02b7 (1 B)
      @0x02bb..0x02bd (3 B)
      @0x02c0..0x02c4 (5 B)
      @0x02c7..0x02c7 (1 B)
      @0x02d4..0x02d5 (2 B)
      @0x02d8..0x02da (3 B)
      @0x02dc..0x02dc (1 B)
      @0x02df..0x02df (1 B)
      @0x02ec..0x02ed (2 B)
  [ITOC[12]] 0x09 HW_MAIN_CFG      SIZE 0x1580 vs 0x980; 734 diff bytes in overlap
      @0x01f0..0x01f0 (1 B)
      @0x01f2..0x01f4 (3 B)
      @0x01f6..0x01f9 (4 B)
      @0x01fb..0x01fb (1 B)
      @0x01fd..0x01fd (1 B)
      @0x0217..0x0217 (1 B)
      @0x021c..0x022f (20 B)
      @0x0231..0x0231 (1 B)
      @0x0233..0x0237 (5 B)
      @0x0239..0x023a (2 B)
      @0x023c..0x023f (4 B)
      @0x0241..0x0241 (1 B)
      @0x0245..0x0247 (3 B)  <- HW_MAIN_CFG+0x245 port0 PCIe gen (16.35 layout)
      @0x024d..0x024e (2 B)
      @0x0250..0x0252 (3 B)
      @0x0256..0x0256 (1 B)
      @0x0258..0x0258 (1 B)
      @0x025a..0x025a (1 B)
      @0x0260..0x0260 (1 B)
      @0x0262..0x0262 (1 B)
      @0x0265..0x0266 (2 B)
      @0x0268..0x026a (3 B)
      @0x0281..0x0281 (1 B)
      @0x0285..0x0287 (3 B)  <- HW_MAIN_CFG+0x285 port1 PCIe gen (16.35 layout)
      @0x028d..0x0293 (7 B)
      @0x0295..0x029b (7 B)
      @0x029d..0x029d (1 B)
      @0x029f..0x02a3 (5 B)
      @0x02a5..0x02ab (7 B)
      @0x02c3..0x02c3 (1 B)
      @0x02c5..0x02c5 (1 B)
      @0x02c7..0x02c7 (1 B)
      @0x02c9..0x02c9 (1 B)
      @0x02cb..0x02cd (3 B)
      @0x0340..0x036b (44 B)
      @0x036d..0x036d (1 B)
      @0x036f..0x0371 (3 B)
      @0x0373..0x0373 (1 B)
      @0x0375..0x0380 (12 B)
      @0x0382..0x0543 (450 B)  <- HW_MAIN_CFG+0x404+ speed tables (16.35 layout)
      @0x0545..0x0546 (2 B)
      @0x054a..0x054e (5 B)
      @0x055e..0x0561 (4 B)
      @0x0564..0x0564 (1 B)
      @0x056b..0x056d (3 B)
      @0x07ca..0x07cb (2 B)
      @0x07ce..0x07cf (2 B)
      @0x07da..0x07da (1 B)
      @0x07ef..0x07ef (1 B)
      @0x07f4..0x082f (60 B)
      @0x0832..0x083d (12 B)
      @0x0840..0x0848 (9 B)
      @0x086c..0x0870 (5 B)
      @0x0910..0x0910 (1 B)
      @0x0912..0x0913 (2 B)
      @0x0917..0x0918 (2 B)
      @0x091a..0x091b (2 B)
      @0x091f..0x0920 (2 B)
      @0x0922..0x0923 (2 B)
      @0x0927..0x0928 (2 B)
      @0x092a..0x092b (2 B)
      @0x092f..0x092f (1 B)
  [ITOC[13]] 0x08 HW_BOOT_CFG      8 diff bytes, 5 ranges
      @0x0000..0x0000 (1 B)
      @0x0023..0x0023 (1 B)  <- HW_BOOT_CFG+0x23 max PCIe speed (0x07=Gen3, 0x0f=Gen4)
      @0x0089..0x008b (3 B)
      @0x00ba..0x00bb (2 B)
      @0x00cc..0x00cc (1 B)
  [ITOC[14]] 0x0b PHY_UC_CONSTS    320 diff bytes, 64 ranges
      @0x05d2..0x05d3 (2 B)
      @0x05d5..0x05d7 (3 B)
      @0x05da..0x05db (2 B)
      @0x05dd..0x05df (3 B)
      @0x05e2..0x05e3 (2 B)
      @0x05e5..0x05e7 (3 B)
      @0x05ea..0x05eb (2 B)
      @0x05ed..0x05ef (3 B)
      @0x05f2..0x05f3 (2 B)
      @0x05f5..0x05f7 (3 B)
      @0x05fa..0x05fb (2 B)
      @0x05fd..0x05ff (3 B)
      @0x0602..0x0603 (2 B)
      @0x0605..0x0607 (3 B)
      @0x060a..0x060b (2 B)
      @0x060d..0x060f (3 B)
      @0x0612..0x0613 (2 B)
      @0x0615..0x0617 (3 B)
      @0x061a..0x061b (2 B)
      @0x061d..0x061f (3 B)
      @0x0622..0x0623 (2 B)
      @0x0625..0x0627 (3 B)
      @0x062a..0x062b (2 B)
      @0x062d..0x062f (3 B)
      @0x0632..0x0633 (2 B)
      @0x0635..0x0637 (3 B)
      @0x063a..0x063b (2 B)
      @0x063d..0x063f (3 B)
      @0x0642..0x0643 (2 B)
      @0x0645..0x0647 (3 B)
      @0x064a..0x064b (2 B)
      @0x064d..0x064f (3 B)
      @0x0652..0x0653 (2 B)
      @0x0655..0x0657 (3 B)
      @0x065a..0x065b (2 B)
      @0x065d..0x065f (3 B)
      @0x0662..0x0663 (2 B)
      @0x0665..0x0667 (3 B)
      @0x066a..0x066b (2 B)
      @0x066d..0x066f (3 B)
      @0x0672..0x0673 (2 B)
      @0x0675..0x0677 (3 B)
      @0x067a..0x067b (2 B)
      @0x067d..0x067f (3 B)
      @0x0682..0x0683 (2 B)
      @0x0685..0x0687 (3 B)
      @0x068a..0x068b (2 B)
      @0x068d..0x068f (3 B)
      @0x0692..0x0693 (2 B)
      @0x0695..0x0697 (3 B)
      @0x069a..0x069b (2 B)
      @0x069d..0x069f (3 B)
      @0x06a2..0x06a3 (2 B)
      @0x06a5..0x06a7 (3 B)
      @0x06aa..0x06ab (2 B)
      @0x06ad..0x06af (3 B)
      @0x06b2..0x06b3 (2 B)
      @0x06b5..0x06b7 (3 B)
      @0x06ba..0x06bb (2 B)
      @0x06bd..0x06bf (3 B)
      @0x06c2..0x06c3 (2 B)
      @0x06c5..0x06c7 (3 B)
      @0x06ca..0x06cb (2 B)
      @0x06cd..0x06cf (3 B)
  [ITOC[15]] 0xa0 SIG_256          256 diff bytes, 1 ranges
      @0x0020..0x011f (256 B)
  [ITOC[16]] 0xa1 PUB_KEYS_2048    identical (0x900)
  [ITOC[17]] 0xa2 FORBIDDEN_VER    identical (0x90)
  [ITOC[18]] 0xa3 SIG_512          510 diff bytes, 3 ranges
      @0x0020..0x0094 (117 B)
      @0x0096..0x0136 (161 B)
      @0x0138..0x021f (232 B)
  [ITOC[19]] 0xa4 PUB_KEYS_4096    identical (0x1100)
  [ITOC[20]] 0x18 ROM_CODE         SIZE 0x64c28 vs 0x6fc28; 407684 diff bytes in overlap
      @0x0006..0x0006 (1 B)
      @0x0022..0x0022 (1 B)
      @0x006d..0x006d (1 B)
      @0x0071..0x0071 (1 B)
      @0x0086..0x0086 (1 B)
      @0x0091..0x0091 (1 B)
      @0x009c..0x009c (1 B)
      @0x009f..0x00a2 (4 B)
      @0x01f0..0x01f1 (2 B)
      @0x0367..0x0367 (1 B)
      @0x036b..0x036b (1 B)
      @0x03ba..0x03ba (1 B)
      @0x04a2..0x04a2 (1 B)
      @0x0aa8..0x0aa8 (1 B)
      @0x0aac..0x0aac (1 B)
      @0x0bef..0x0bef (1 B)
      @0x0c28..0x0c28 (1 B)
      @0x0c60..0x0c61 (2 B)
      @0x0c6e..0x0c6e (1 B)
      @0x0c74..0x0c74 (1 B)
      @0x0c7d..0x0c7d (1 B)
      @0x0c8f..0x0c8f (1 B)
      @0x0c94..0x0c94 (1 B)
      @0x0c96..0x0cad (24 B)
      @0x0caf..0x0ccb (29 B)
      @0x0ccd..0x0cf3 (39 B)
      @0x0cf5..0x0d1c (40 B)
      @0x0d1f..0x0d22 (4 B)
      @0x0d24..0x0d63 (64 B)
      @0x0d65..0x0d78 (20 B)
      @0x0d7a..0x0e63 (234 B)
      @0x0e65..0x0e81 (29 B)
      @0x0e83..0x0e84 (2 B)
      @0x0e86..0x0ea8 (35 B)
      @0x0eaa..0x0ebd (20 B)
      @0x0ebf..0x0eea (44 B)
      @0x0eec..0x0f0c (33 B)
      @0x0f0e..0x0f8e (129 B)
      @0x0f90..0x0fa3 (20 B)
      @0x0fa6..0x0faa (5 B)
      @0x0fad..0x102c (128 B)
      @0x102e..0x1037 (10 B)
      @0x103a..0x103a (1 B)
      @0x103e..0x1055 (24 B)
      @0x1057..0x1076 (32 B)
      @0x1078..0x107c (5 B)
      @0x107f..0x10b0 (50 B)
      @0x10b2..0x10e9 (56 B)
      @0x10eb..0x1104 (26 B)
      @0x1107..0x111b (21 B)
      @0x111d..0x1129 (13 B)
      @0x112c..0x1138 (13 B)
      @0x113a..0x1176 (61 B)
      @0x1178..0x117d (6 B)
      @0x117f..0x1190 (18 B)
      @0x1192..0x11c5 (52 B)
      @0x11c7..0x12ed (295 B)
      @0x12ef..0x1314 (38 B)
      @0x1316..0x140b (246 B)
      @0x140d..0x1560 (340 B)
      @0x1562..0x1569 (8 B)
      @0x1606..0x1606 (1 B)
      @0x1622..0x1622 (1 B)
      @0x162c..0x162c (1 B)
  [ITOC[21]] 0x30 DBG_FW_INI       SIZE 0xbf4 vs 0xd1c; 3035 diff bytes in overlap
      @0x0002..0x0002 (1 B)
      @0x0004..0x0004 (1 B)
      @0x0007..0x000f (9 B)
      @0x0012..0x0022 (17 B)
      @0x0029..0x005b (51 B)
      @0x005d..0x00b0 (84 B)
      @0x00b2..0x0268 (439 B)
      @0x026a..0x02ad (68 B)
      @0x02af..0x0414 (358 B)
      @0x0416..0x0504 (239 B)
      @0x0506..0x05f2 (237 B)
      @0x05f4..0x0631 (62 B)
      @0x0633..0x081d (491 B)
      @0x081f..0x0870 (82 B)
      @0x0872..0x087d (12 B)
      @0x087f..0x0ae5 (615 B)
      @0x0ae7..0x0bf3 (269 B)
  [ITOC[22]] 0x32 DBG_FW_PARAMS    identical (0x8)
  [ITOC[23]] 0xe9 CRDUMP_MASK      SIZE 0x10000 vs 0x8d30; 10244 diff bytes in overlap
      @0x0000..0x0046 (71 B)
      @0x0048..0x0056 (15 B)
      @0x0058..0x009f (72 B)
      @0x0804..0x0807 (4 B)
      @0x0809..0x0809 (1 B)
      @0x080c..0x087f (116 B)
      @0x0884..0x0887 (4 B)
      @0x088d..0x08a4 (24 B)
      @0x08a8..0x08ac (5 B)
      @0x08b0..0x08b0 (1 B)
      @0x08c0..0x08c2 (3 B)
      @0x0900..0x0918 (25 B)
      @0x0920..0x0938 (25 B)
      @0x0940..0x0958 (25 B)
      @0x0960..0x0978 (25 B)
      @0x0980..0x0991 (18 B)
      @0x09a0..0x09b8 (25 B)
      @0x09c0..0x09cf (16 B)
      @0x09d2..0x09da (9 B)
      @0x09dc..0x09de (3 B)
      @0x09e0..0x09f8 (25 B)
      @0x0a00..0x0a18 (25 B)
      @0x0a20..0x0a31 (18 B)
      @0x0a40..0x0a51 (18 B)
      @0x0a60..0x0a68 (9 B)
      @0x0a70..0x0a72 (3 B)
      @0x0a74..0x0a76 (3 B)
      @0x0a78..0x0a7a (3 B)
      @0x0a7c..0x0a7e (3 B)
      @0x0a81..0x0a82 (2 B)
      @0x0a84..0x0a8a (7 B)
      @0x0aa0..0x0abf (32 B)
      @0x0b00..0x0b05 (6 B)
      @0x0b08..0x0b0d (6 B)
      @0x0b10..0x0b13 (4 B)
      @0x0b20..0x0b2a (11 B)
      @0x0b40..0x0b5f (32 B)
      @0x0b80..0x0b88 (9 B)
      @0x0b8c..0x0b92 (7 B)
      @0x0ba0..0x0ba5 (6 B)
      @0x0ba8..0x0bad (6 B)
      @0x0bb0..0x0bb3 (4 B)
      @0x0c00..0x0c06 (7 B)
      @0x0c08..0x0c0f (8 B)
      @0x0c20..0x0c28 (9 B)
      @0x0c2c..0x0c32 (7 B)
      @0x0c80..0x0c9f (32 B)
      @0x0ca2..0x0ca6 (5 B)
      @0x0ca8..0x0caf (8 B)
      @0x0d00..0x0d04 (5 B)
      @0x0d06..0x0d10 (11 B)
      @0x0d20..0x0d34 (21 B)
      @0x0d37..0x0d39 (3 B)
      @0x0d3c..0x0d43 (8 B)
      @0x0d45..0x0d45 (1 B)
      @0x0d48..0x0d4c (5 B)
      @0x0d50..0x0d54 (5 B)
      @0x0d60..0x0d63 (4 B)
      @0x0d65..0x0d66 (2 B)
      @0x0d6d..0x0d73 (7 B)
      @0x0d80..0x0d85 (6 B)
      @0x0d88..0x0d8b (4 B)
      @0x0da0..0x0da1 (2 B)
      @0x0da3..0x0da7 (5 B)
  [ITOC[24]] 0xeb PROG_HW_FW1      identical (0x50000)
  [DTOC[0]] 0xe5 FW_NV_LOG        identical (0x10000)
  [DTOC[1]] 0xe6 NV_DATA0         identical (0x10000)
  [DTOC[2]] 0xe4 NV_DATA2         identical (0x10000)
  [DTOC[3]] 0xe1 DEV_INFO         identical (0x200)
  [DTOC[4]] 0xe1 DEV_INFO         identical (0x200)
  [DTOC[5]] 0xe0 MFG_INFO         4 diff bytes, 2 ranges
      @0x0000..0x0002 (3 B)
      @0x000c..0x000c (1 B)
  [DTOC[6]] 0xe3 VPD_R0           identical (0x0)
```

Краткие выводы — какие поля/области различаются (раскладка для следующего
скоупа, 56G/IB; аннотации тула — офсеты 16.35-раскладки, где помечено):

- **identical**: 0x20, 0x0a, 0x0c, 0x32, 0xeb, 0xa1, 0xa2, 0xa4 и весь DTOC,
  кроме 0xe0 MFG_INFO (4 B: @0x0..0x2, @0xc).
- **0x08 HW_BOOT_CFG** — 8 diff bytes: @0x23 = **max PCIe speed**
  (6120: `0x0f` = Gen4, 4030: `0x07` = Gen3; §1.5) + @0x0, @0x89..0x8b,
  @0xba..0xbb, @0xcc.
- **0x09 HW_MAIN_CFG** — `SIZE 0x1580 vs 0x980` + 734 diff bytes в пересечении:
  **port PCIe gen** @0x245/0x285 (16.35-раскладка), **speed-таблицы**
  @0x404+ (450 B, 16.35-раскладка), 60 B @0x7f4..0x82f.
- **0x11 FW_BOOT_CFG** — `SIZE 0x400 vs 0x4c0` + 298 diff bytes: **device_id**
  low byte @0x2d, **subsystem_id** @0x3d, **PCIe cap_index** @0x93
  (у 4030 — `0x45`; §1.5), 32 B @0x9c..0xbb, 34 B @0x100..0x121.
- **0x12 FW_MAIN_CFG** — `SIZE 0xc00 vs 0xb00` + 1300 diff bytes: 16 B
  @0xec..0xfb, 10 B @0x168..0x171, россыпь 1-B-дельт с периодом 4 B
  @0x200..0x2a3 (per-port таблица: скорости/режим портов — точная
  16.27-раскладка = следующий скоуп).
- **0x10 IMAGE_INFO** — 141 diff bytes: version/флаги @0x3..0x1d,
  subsystem @0x20..0x23, **PSID** @0x24.., module_versions/prod_ver
  @0x196..0x1cc, **description** @0x1d0+, **name** @0x340+, **prs_name**
  @0x384..0x399.
- **0x30 DBG_FW_INI** — `SIZE 0xbf4 vs 0xd1c` + 3035 diff bytes — PRS-текст
  (Dell PRS побайтово сверен в §1.2).
- Подписи 0xa0/0xa3 различаются (OEM-подписи); кодовые секции
  0x02/0x03/0x04/0x05/0x06/0x07/0x18 и 0xe9 CRDUMP_MASK — `SIZE` (размеры
  различаются) + diff в пересечении (разные релизы).

### 1.5 Gen4-значения в Dell-бинарном конфиге

Скрипт стадии 0 читает ITOC-секции Dell-образа 6120
(0x08/0x09/0x10/0x11/0x12): `0x08+0x23` (`max_speed`), `0x11+0x93`
(`cap_index`), `0x09` (port gen), `0x11+0x2d`/`0x12+0x2d` (|0x1000),
`0x10` (`pci_device_id` @0x1c, LE u16). Вывод:

```
0x08+0x23 max_speed   = 0xf
0x11+0x93 cap_index   = 0x0
0x09+0x245 port0 gen  = 0x0
0x09+0x285 port1 gen  = 0x0
0x11+0x2d (|0x1000)   = 0x1002
0x12+0x2d (|0x1000)   = 0x10aa
0x10 pci_device_id    = 0x1910
```

`0x10 pci_device_id` — чтение LE u16 в скрипте неверно по байтовому порядку:
в on-flash layout поле **BE u16** (mstflint `tools_layouts/cibfw_layouts.h`,
DWORD[7] @0x1c: низкие 16 бит = `pci_vendor_id` @0x1e, старшие 16 =
`pci_device_id` @0x1c; `connectx4_image_info_unpack` →
`adb2c_pop_bits_from_buff` — big-endian). Верификация: `xxd` по секции
@0x3c4cb4 — байты `10 19 15 b3` @0x1c..0x1f → **device_id = `0x1019`
(4121, CX-5 Ex)**, vendor `0x15b3`; совпадает с Dell PRS
(`pcie_cfg_data.pci_cfg_space.cfg_hdr.device_id = 4121`) и спека §2
(Dell 4121/`0x1019` vs HPE 4119/`0x1017`; у 4030 проверено — `0x1017`).

Выводы:

- Dell-конфиг — **Gen4** по `HW_BOOT_CFG+0x23 = 0x0f` (у 4030 — `0x07`).
- 16.27-раскладка отличается от 16.35: `FW_BOOT_CFG+0x93 = 0x00`
  (у 4030 — `0x45`); port gen @0x245/0x285 в 0x09 — `0x00`/`0x00`
  (оффсеты — 16.35-раскладка, в 16.27 поле в другом месте).
- Формула device_id `FW_BOOT_CFG+0x2d|0x1000` (`docs/250-re/100-formats/060-chip-map.md`) на 16.27
  **не сходится** (`0x1002`); device_id фактически — из `0x10`
  (`0x1019` = 4121) и PRS.

## 2. Стадия 1 — сборка, флеш, бут

### 2.1 Сборка

`python3 mlxfwutil.py repack` (из корня репо, 2026-09-08;
`<hpe4030>`/`<dell6120>` — образы §1.1):

```
$ python3 mlxfwutil.py repack --new <hpe4030> --old <dell6120> --prio new -o build/dell_s1_newprio.bin
build/dell_s1_newprio.bin: 16777216 bytes, md5 7f2adf2da28d5b0a00ebf4e85f57ed71
$ python3 mlxfwutil.py repack --new <hpe4030> --old <dell6120> --prio old -o build/dell_s1_oldprio.bin
build/dell_s1_oldprio.bin: 16777216 bytes, md5 1b2498f82479eb9bddfee5cc9a446f5a
```

| Образ | md5 | `verify` | `mstflint q` |
|---|---|---|---|
| `dell_s1_newprio.bin` | `7f2adf2da28d5b0a00ebf4e85f57ed71` | RESULT: PASS (ITOC 25 + DTOC 7 sections, all CRC OK) | без ошибок: FS4, FW 16.35.4030, PSID DEL0000000004, UEFI 14.29.15 / PXE 3.6.902 |
| `dell_s1_oldprio.bin` | `1b2498f82479eb9bddfee5cc9a446f5a` | RESULT: PASS (ITOC 25 + DTOC 7 sections, all CRC OK) | без ошибок: FS4, FW 16.35.4030, PSID DEL0000000004, UEFI 14.29.15 / PXE 3.6.902 |

`mstflint -i <образ> q` (mstflint 4.36.0, офлайн-запрос файла) — вывод
одинаковый у обоих образов:

```
Image type:            FS4
FW Version:            16.35.4030
FW Release Date:       27.6.2024
Product Version:       rel-16_35_4030
Rom Info:              type=UEFI version=14.29.15 cpu=AMD64
                       type=PXE version=3.6.902 cpu=AMD64
Description:           UID                GuidsNumber
Base GUID:             N/A                     8
Base MAC:              N/A                     8
Image VSD:             N/A
Device VSD:            N/A
PSID:                  DEL0000000004
Security Attributes:   secure-fw
Security Ver:          0
```

Оба образа — 4030-версии FW/ROM + Dell-PSID, ошибок нет.

Тесты тула (спека §8) — `python3 -m pytest tests/test_mlxfwutil.py::TestRepack`
(5 passed): S1-new ≡ 4030 (кроме merge-0x09/0x12, 0x10/0x30/0xE\*):
OK (юнит-тест); diff(S1-old, S1-new) только конфиг-секции: OK (юнит-тест)

> **Обновление (R7/R8, 2026-09-08).** Dense-укладка (md5 выше) **не бутится**
> (§2.3). repack переписан **layout-preserving** (все секции по адресам 4030;
> выросшие 0x09/0x12/0xe9 — в 0xFF-gap; DTOC device data — из 4030, не Dell).
> Финальные образы: `dell_s1_newprio.bin` md5 **61dfbd39fb7eb70809bfbb51bf627e57**,
> `dell_s1_oldprio.bin` md5 **2748a8bef2cb6d78fa7f25249fd9ebeb** — verify PASS,
> `mstflint q` как в таблице выше. Тесты: **28/28 PASS** (было 5). Детали — §2.4,
> §3 (R7/R8).

### 2.2 FNP-флеш + cold boot

Карта в FNP (vendor:device **15b3:020d**). PCI-адрес — **искать по vendor:device,
не хардкодить** (после power cycle адреса сдвигаются, §2.4); на момент флеша —
41:00.0.

**S1-new (canary), 1-й образ (dense-укладка, §2.1, md5 7f2adf2d…).** PSID: flash
HPE0000000009 (docs/750-exp/160-hpe-cx5-vpi-gen4-precheck) → образ DEL0000000004 ⇒ нужен `--allow_psid_change` (R6):

```
$ mstflint -d 41:00.0 -i /var/roothome/dell_s1_newprio.bin -y --allow_psid_change burn
... Burning FW image without signatures - OK
... Failed to update FW boot address        (штатно при FNP-восстановлении, docs/750-exp/160-hpe-cx5-vpi-gen4-precheck §10)
... Restoring signature - OK
```

Владелец: FNP off + cold power cycle → проверка бута (§2.3).

**S1-old** — не флешился: после no-boot S1-new дерево решений (спека §5) ведёт в
recovery, S1-old не проверялся.

### 2.3 Проверка бута

Критерий (спека §5): `lspci` (device_id), `mstflint q` (FW 16.35.4030),
порт0-линк.

| Образ | lspci | `q` | порт0 | порт1 (бонус) |
|---|---|---|---|---|
| S1-new (1-й, dense) | **карты нет в PCI** (ни 0x1017, ни 0x020d в `lspci -nn -d 15b3:`) | — | — | — |
| S1-new (2-й, layout-preserving) | **остаётся в FNP** (15b3:020d, mstflint не читает) | — | — | — |
| S1-old | не проверялся | — | — | — |

**S1-new: НЕТ бута** (оба образа). Владелец подтвердил отсутствие карты в PCI
после 1-го флеша. → дерево решений спека §5: ветка «no-boot» → recovery (§2.4).

### 2.4 Recovery / инциденты

**Инцидент 1 — no-boot S1-new (dense, §2.3).** Карта отсутствует в PCI. PCI-
адреса после power cycle сдвинулись: прежний 41:00.0 — чужая CX-4 (15b3:1013),
01:00.0/81:00.0 — чужие CX-5 Ex (15b3:1019). **Вывод: PCI-адрес не хардкодить.**

**R7 — root-cause (офлайн, по FNP-дампу flash).** Рабочая гипотеза: dense-
реукладка ломает бут (56G-патч той же 4030-базы с изменениями только в содержимом
0x08/0x09/0x12 бутится; S1 со сдвигом секций — нет). Исключены: RSA-подпись
(docs/750-exp/160-hpe-cx5-vpi-gen4-precheck §10.5 — ROM бутит 56G с битой RSA), begin_area/hw_pointers (CRC-поле
`toc_ptr` — calc_hw_crc от указателя, в S1-new валиден; §3.1), magic, gap-область.
**FIX: repack layout-preserving.** Детали — §3 (R7/R8).

**Откат (R7).** FNP-окно, карта снова 41:00.0 (15b3:020d), flash q = S1-new.
Дамп flash `s1new_flash_dump.bin` (md5 **718ecf…**, локально `/tmp/flash_dump.bin`).
Запись known-good `hpe_final_56g_gen4.bin` (md5 **e6a85172…**) c
`--allow_psid_change` (DEL→HPE): «Burning FW image without signatures - OK» /
«Restoring signature - OK». Дамп good-flash `flash_good_dump.bin`
(md5 **205c6ec4…**, локально `/tmp/flash_good_dump.bin`). Post-rollback q:
HPE0000000009, 16.35.4030. Карта в FNP с 56G.

**R8 — fix + rebuild + re-burn.** repack переписан layout-preserving (28/28 PASS),
DTOC device data — из 4030. Новые образы:
- `build/dell_s1_newprio.bin` md5 **61dfbd39fb7eb70809bfbb51bf627e57**
- `build/dell_s1_oldprio.bin` md5 **2748a8bef2cb6d78fa7f25249fd9ebeb**

Оба: verify PASS, `mstflint q` OK (DEL0000000004, 16.35.4030, secure-fw). 2-й
флеш S1-new (layout-preserving) из FNP c `--allow_psid_change` (HPE→DEL):
«Burning OK» / «Failed to update FW boot address» (штатно) / «Restoring
signature OK». Владелец: FNP off + cold cycle → **опять no-boot** (карта остаётся
в FNP, mstflint не читает).

**A/B-анализ (raw-дамп flash, `flint -d 41:00.0 rb 0x0 0x1000000`, md5
c178109a…, локально `/tmp/flash_raw_local.bin`).** 16 МиБ flash = два слота по
8 МиБ (0x0 / 0x800000), **контигуальные половины, raw маппится 1:1 на первые
8 МиБ файла образа** (коррекция 2026-09-09: «chunk-interleaved 128K» — ошибка,
0x17 прочитан как decimal 17; см. docs/750-exp/110-dell-base-rework §A/B.2):
- слот **0x0** — 56G, **magic «MTFW» стёрт** (невалидирован burn-ом);
- слот **0x800000** — S1-new, magic цел;
- **boot-addr → 0x0**. Failsafe-обновление boot-addr для FS4 идёт через ISFU
  работающим FW — в FNP невозможно ⇒ «Failed to update FW boot address».
  ROM читает 0x0 → стёртый magic → FNP.

**Reframe: no-boot — скорее всего stale A/B boot-addr**, не (только) dense-
укладка. 56G (docs/750-exp/160-hpe-cx5-vpi-gen4-precheck) прошёл тот же flow и бутится ⇒ сам механизм на этой карте
работает; no-boot — либо stale-addr, либо сам S1-new (слепой merge 16.35+16.27)
не валиден. Однозначно без ROM-кода не разделить (§3.1).

**Тест A (бисекция): Dell 6120 vendor-образ.** Файл валиден (verify PASS), но
burn из застрявшего состояния → «Burning FS4 image failed: Bad CRC». Bad CRC —
артефакт device-query (mstflint следует по boot-addr в невалидированный 0x0),
не файла.

**Попытки восстановления 56G (mstflint) — все упали:**
- failsafe `hpe_final_56g_gen4.bin` → «Bad CRC»;
- `--nofs` → «Failed to align the device sections: FW_NV_LOG section was not found!»;
- `--nofs --ignore_dev_data` → «Burning FW image without signatures - OK», затем
  C++-assertion **SIGABRT (exit 134)**, `std::vector::operator[] '__n < this->size()'`.

Post-burn raw (md5 **4fbc2f03…**, локально `/tmp/flash_after56g_local.bin`):
190-B-дельта против предыдущего дампа; среди прочего — 0x0 magic
`00000000`→`ffffffff` (стёрт) + 174 B @0xfb0000 (device data 56G); слот
**0x800000 — по-прежнему S1-new** (тело образа не записано). Flash в **смешанном**
состоянии.

**Итог:** mstflint-ом карта из этого состояния **не восстанавливается**
(failsafe — Bad CRC; nofs — align-fail; nofs --ignore_dev_data — crash +
неполная запись). **Владелец: перезапись 56G — вручную.** Агент карту не трогает.

**Состояние flash на момент передачи владельцу (raw md5 4fbc2f03…):** S1-new в
слоте 0x800000 (magic цел), слот 0x0 стёрт (magic `0xffffffff`), device data 56G
@0xfb0000; boot-addr → 0x0; карта в FNP.

## 3. Отклонения от плана (R1–R8) и root-cause no-boot

Все отклонения — **ruling → план-фикс отдельным `docs:`-коммитом**
(english-commits). Реестр: `.superpowers/sdd/progress.md`.

| # | Тип | Суть | Разрешение |
|---|---|---|---|
| R1 | план-дефект | `test_layout` assert `s >= 0x5380`; фактически packed-ITOC стартует @0x5360 (25 ITOC + END) | константа теста → 0x5360; план: 918ba7e |
| R2 | конфиг opencode | agent sdd-implementer ссылался на несущ. модель `local-llama-cpp/medium` | → `pigoky-llama-cpp/medium`; рестарт opencode |
| R3 | план-дефект | II_NAME (0x340, 65): name[65] перекрывает prs_name[0] @0x380 | → name[64] (noop byte-identical); план: d1f5f99 |
| R4 | план-дефект ×2 | (a) repack не писал payload секций в `out`; (b) roundtrip-тест `find_entry` ломается на дубле DTOC 0xE1 | (a) `out[addr:addr+len]=data`; (b) `entry_at(e.toc, e.index)`; план: 34e5e77 |
| R5 | план-дефект | IMAGE_INFO+0x1c `pci_device_id` читался LE u16; поле **BE u16** (Dell 0x1019/4121, HPE 0x1017/4119) | → BE; план: 0c9ea4d |
| R6 | план-дефект | burn с переходом PSID (HPE→DEL) без `--allow_psid_change` → «PSID mismatch» | → `-apc`; план-фикс Task 8/9 |
| R7 | нет-бут | root-cause no-boot S1-new: рабочая гипотеза — dense-реукладка; FIX — layout-preserving repack | реализовано в R8; план-фиксы (Facts-укладка, rollback cmd) |
| R8 | нет-бут (fix) | layout-preserving repack; DTOC device data из 4030; rebuild; re-burn; post-burn A/B-анализ | 28/28 PASS; rebuild 61dfbd39/2748a8be; plan/spec/docs-95 §1.3 |

### 3.1 Root-cause no-boot — состояние вопроса

**Доказано (raw-дампы + md5):**
- good 56G: образ в слоте 0x0, magic цел, бутится (docs/750-exp/160-hpe-cx5-vpi-gen4-precheck + дамп 205c6ec4…).
- S1-new (dense, 718ecf…) → no-boot (карта не в PCI).
- S1-new (layout-preserving, c178109a…) → no-boot (FNP); слот 0x800000 = S1-new
  (magic цел), слот 0x0 = 56G (magic стёрт), boot-addr → 0x0.
- Dell 6120 vendor-файл валиден (PASS), но burn из застрявшего состояния → Bad CRC.

**Кандидаты причины (без ROM-кода не разведены):**
1. **Stale A/B boot-addr** — ROM читает 0x0 (невалидирован, стёртый magic) → FNP;
   failsafe-обновление addr невозможно в FNP («Failed to update FW boot address»).
   Рабочая гипотеза (reframe сессии).
2. **Невалидный S1-new** — слепой побайтовый merge 16.35-базы + 16.27-конфига
   (0x09/0x10/0x12/0x30/0xe9) при разной раскладке полей (§1.4) ⇒ внутренне
   непротиворечивый конфиг не гарантирован.
3. ~~Dense-укладка~~ (гипотеза R7) — **ослаблена**: layout-preserving rebuild тоже
   не бутится; полностью не исключена (накладывается на 1/2).

**Исследовано и исключено: begin_area / hw_pointers — «свой CRC» у `toc_ptr`
(«Jackpot»-расследование, офлайн по FNP-дампу).** Заголовок образа (begin_area)
несёт `hw_pointers` (carmel), `FS4_HW_PTR_START=0x18`: 16 записей × 8 B (0x18..
0x98). Запись `toc_ptr` @0x28/0x2C: ptr=0x5000, crc=0x5658 (4030); ptr=0x4000,
crc=0xBD3F (Dell). У репака begin_area скопирован **дословно** из 4030 ⇒ в S1-new
остаются 0x5000/0x5658, хотя наша ITOC-таблица отлична от 4030-й (3+ записи
изменены) ⇒ гипотеза: crc — CRC *содержимого* ITOC ⇒ в S1-new stale ⇒ no-boot.
- crc **не** совпадает с CRC содержимого ITOC (entries-only, header+entries,
  варианты endianness) — проверено офлайн.
- **Алгоритм (найден, сверен по 5 записям 4030+Dell):** `crc16 =
  calc_hw_crc(ptr32[4B] + [00 00])` (`mft_utils/calc_hw_crc.c`): toc 4030=0x5658,
  tools=0x8359, bootrec=0x75F8, boot2=0xEB67, toc Dell=0xBD3F — все совпали. CRC
  — **функция значения указателя**, а не указываемого содержимого.
- **Вывод:** `toc_ptr` в S1-new не менялся (0x5000) ⇒ сохранённый 0x5658 =
  calc_hw_crc(0x5000) **всё ещё валиден** ⇒ **begin_area/hw_pointers исключён**
  как причина no-boot. (R8: ptr = байты 0-3 записи, **без** сдвига — decode R7
  `addr<<8` неточен; CRC-поле (байты 6-7) валидно и в S1-new не меняется.)

Нюанс: 56G прошёл тот же flow (failsafe burn из FNP c «Failed to update FW boot
address») и **бутится** ⇒ сам A/B-механизм на карте работает. Значит, либо ROM
коммитит валидный новый образ (и тогда S1-new невалиден — пункт 2), либо 56G-
flow отличался. Развести без ROM-кода нельзя.

**Реаттрибуция (2026-10-31, цикл repack-burn-safety — см. docs/250-re/100-formats/050-fs4-burn-order.md).**
Повреждения S1-new (layout-preserving, c178) объяснены и побайтово
воспроизведены симуляцией write-механики burn: **sector-erase без RMW при
нарушении инварианта «порядок ITOC-записей == монотонный рост адресов»**
(разведка `2026-10-31-repack-relocation-recon.md` §3.5-§3.6; чекер
`burn_order_check`, 11/11 повреждённых секций слота B == симуляции,
журнал task-01). «Truncation @0x430000» (docs/750-exp/110-dell-base-rework §A/B.4) — НЕ truncation:
FF-хвосты 0x02/0x18 лежат на границах 64K-секторов, стёртых revisit-записями
более поздних ITOC-записей (0x11/0x08 → сектор 0x430000; 0xeb → 0x4b0000 и
0x500000). Следствие для кандидатов выше: **no-boot = механическое следствие
неполноты слота B** (8 секций FF + хвосты 0x02/0x18 → ROM отклоняет слот,
docs/750-exp/110-dell-base-rework §A/B.5); «stale boot-addr» (п. 1) вторичен (ROM и так сканирует оба
слота); blind-merge (п. 2) не был решающим фактором для layout-preserving
случая — повреждение механическое. S1-dense (первый burn): артефакты утрачены
— неразрешимо офлайн. Классификация 0x32 в §A/B.4 («записана») — по симуляции
должна быть «стёрта»; дамп c178 утрачен, перекрёстная проверка невозможна.

**Обоснованный merge (следующий скоуп)** — §4 и `TODO.md` «Переработка фазы
Dell-база».

## 4. Следующий скоуп: обоснованный merge (вместо слепого)

Текущий S1-merge — **слепой побайтовый splice двух версий FW**: для MERGE_TYPES
(0x08/0x09/0x11/0x12, mlxfwutil.py:365) `merge_section(prio, other)` (mlxfwutil.py:369) =
`prio`, если `len(prio) >= len(other)`, иначе `prio + other[len(prio):]`
(спека §3). Раскладка полей 16.35 и 16.27 различается (§1.4: разные размеры и
офсеты у одних и тех же логических полей), поэтому splice даёт «франкенштейн»-
конфиг — кандидат на no-boot (§3.1, п. 2).

Переработка — `TODO.md` → «Переработка фазы Dell-база: более мелкие шаги»;
принцип **одно изменение за раз** (каждый шаг проверяем: бут + `mstflint q` +
линк):
1. **Не-secure-fw карта** для экспериментов — убрать переменную «подпись».
2. **Section-уровень, по одной секции**: (a) только `.ini` (0x30); (b) в EN-
   прошивке только код FW (заменить code-секции, не трогая secure-fw секции);
   (c) EN-конфиг → VPI (0x10 PSID + конфиг-секции).
3. **Обоснованный (не слепой) merge** 0x08/0x09/0x11/0x12: сначала раскладка
    полей (`mlxfwutil.py diff 4030↔Dell`, стадия 0 → `docs/750-exp/100-dell-base-vpi-build`), merge **по полям**,
   а не «префикс+хвост».
4. **A/B dual-slot + boot-addr**: понять/верифицировать раскладку и обновление
   boot-адреса (в FNP через running FW не обновляется) + надёжный burn/recovery —
   кандидат §3.1.1.
