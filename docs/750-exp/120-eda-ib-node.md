# 120. EDA → IB-узел: результаты фазы (по главам)

Дата: 2026-09-10. Спека: `docs/superpowers/specs/2026-09-10-eda-ib-node-design.md`.
План главы 1: `docs/superpowers/plans/2026-09-10-eda-ib-node-ch1.md`.
Журналы: `docs/superpowers/journal/2026-09-10-eda-ib-node-ch1-task-01/02/03.md`.

## 1. Глава 1 — precheck («very start»)

Полигон: MCX556A-EDA, 15b3:1019, PSID `MT_0000000009`, 16.35.4030, FS4,
non-secure, VPI (IB+ETH, default IB), Gen4 x16; Base GUID
реестр `CARD_CX5_EDR100_GUID`/8, Base MAC реестр `CARD_CX5_EDR100_MAC`/8. Кабель port1 → фабрика
Inviniscale-IV (QDR) — уже воткнут (владелец).

### 1.1 Baseline (T1.1)

Журнал: `…/2026-09-10-eda-ib-node-ch1-task-01.md`.

- BDF: **81:00.0/81:00.1** (идентификация заново: 15b3:1019 + PSID
  `MT_0000000009`; 01:00.x — тот же 1019, PSID `MT_0000000361`, не наша).
- Темп (до/после): 61000/61000 мК (61.0 °C, EDA hwmon3/4); максимум по всем
  чтениях 61000 < 75000.
- `mstconfig q -e`: link-type-параметр = **`LINK_TYPE_P1`/`LINK_TYPE_P2`**
  (per-port; DB-подсказка `LINK_TYPE[0/1]` реальному выводу не соответствует):
  port0 — Default `IB(1)` / Current `ETH(2)` / Next Boot `ETH(2)`;
  port1 — то же. **NV-override ETH подтверждён** (при default IB в образе
  порты работают в Ethernet — вопрос T1.3, ответ §1.3).
- ibstat / ip / ethtool: port0 (mlx5_2, `enp129s0f0np0`) — Active/LinkUp
  Rate 100, Ethernet, 100G DAC up; port1 (mlx5_3, `enp129s0f1np1`) —
  Down/Disabled, «No cable» в ETH-режиме (не показатель физики).
- PRS `dc`: md5 `6eafa5431a97bffa5470d94333157871` — побайтово идентичен
  срезу 00:34 (`…/2026-09-10-eda-card-dc.txt`); VPI, default IB, оба порта.
- `ri` 4030-EDA: `refs/fw/cx-5-6/4030_eda_ri.bin` (16MiB), md5
  `27fb16c0a68311eacd8cfe6dad35f071` — бэкап «нашей прошивки».
- raw host: `refs/fw/cx-5-6/dumps/t11_raw_host.bin` md5
  `a84545e554b31a25a4b022e737f7ee05`; raw container (t-mlxflint):
  `dumps/t11_raw_container.bin` md5 `a84545e554b31a25a4b022e737f7ee05`.
- **md5 host == container: ДА** ⇒ raw-инструмент фазы — **host mstflint**
  (fallback t-mlxflint проверен эквивалентен; `rw` не упражнялся —
  raw-записей в фазе нет).
- `ab` (оба raw): slot A valid (ITOC @0x5000, 25 ent, psid `MT_0000000009`,
  ver rel-16_35_4030), slot B erased (magic), MTCF @0x7ff000; valid slots = A.

### 1.2 IB на фабрике (T1.2)

Журнал: `…/2026-09-10-eda-ib-node-ch1-task-02.md`.

- `mstconfig set` (оба порта → IB), дословно (host mstconfig не работает —
  нет DB; t-adm, MFT 4.36):
  `podman-remote -c root-mellanox exec t-adm mstconfig -d 81:00.0 -y set LINK_TYPE_P1=IB LINK_TYPE_P2=IB`
  (rc=0; значение — enum-имя `IB`, не `IB(1)` — по mstflint-источнику
  `EnumParamValue::parseValue`). До set: Next Boot ETH(2); после set:
  Next Boot IB(1); после reboot: **Current IB(1)** оба порта.
- Reboot: 14:12:07 → up 14:15:35 (~3.5 мин); PCI-класс 81:00.x
  `[0200]`→`[0207]` (InfiniBand controller — ожидаемый IB-эффект).
- port1 (mlx5_3, Node GUID — реестр `CARD_CX5_EDR100_P1_GUID`) ibstat: **Link layer
  InfiniBand, State Active, Physical LinkUp, Rate 40 (= QDR 4x, per-lane
  10 Gb/s — даун-негот. EDR→QDR; тот же свитч дал Rate 40 на HPE-IB-порту,
  docs/750-exp/160-hpe-cx5-vpi-gen4-precheck §2), Base lid 13, SM lid 1** — все критерии успеха выполнены.
- port0 (mlx5_2, `…4e`): **тоже Active** (LID 16, Rate 40, SM lid 1) —
  бонус: оба порта встали в фабрику (port0 через DAC); плановое «DAC down —
  ожидаемо» не материализовалось.
- Примечание: фабрика поднимается ~4–5 мин после reboot (SM discovery) —
  ранний ibstat (Down) = ложный негатив.
- raw post-IB: `dumps/t12_raw_postib.bin` (16MiB) md5
  `659d3001b48bdad960f3991565acfbf5` (≠ T1.1 — NV-конфиг изменился); `ab`:
  slot A valid (psid 0009, rel-16_35_4030), slot B erased — как T1.1.
- Темп: все 6 чтений (до set / pre-reboot / post-reboot / post-IB-up / после
  raw) max 63000 мК (63 °C) < 75000.
- **Вердикт дискриминатора (§0(b) спеки): ВЫПОЛНЕНО.** Вендорный 4030-VPI
  (без burn) + та же фабрика/кабель зацепились за IB **до любых перешивов**
  (оба порта Active) ⇒ **свитч/кабель исключены как причина E5-25G**;
  дальше любой сбой IB = вопрос образа (конфиг/PHY).

### 1.3 PRS с активным IB + byte-diff (T1.3)

Журнал: `…/2026-09-10-eda-ib-node-ch1-task-03.md`.

- PRS: `…/2026-09-10-eda-ib-node-ch1-t13-dc-ib.txt` md5
  `6eafa5431a97bffa5470d94333157871` — **== T1.1** (`dc` = ini **образа**
  (0x30 DBG_FW_INI), NV-override и активный линк в PRS не отражаются).
- raw: `dumps/t13_raw_postib.bin` md5 `659d3001b48bdad960f3991565acfbf5`
  — **== T1.2** (флеш не менялся с T1.2).
- **byte-diff T1.1↔T1.3** (`mlxfwutil.py ab --diff`, перепроверено
  независимо, вкл. `cmp -l`): **208 B, только slot B**; диапазоны (физ.):
  0xFB0458, 0xFB0468, 0xFB04AC–0xFB04CB (32 B), 0xFB1244, 0xFB1254,
  0xFB1264–0xFB130F (172 B); slot A — identical. Все 6 диапазонов ⊂
  **DTOC-секции `0xE6 NV_DATA0`** @0xFB0000 (size 0x10000; секц.-офсеты
  0x458..0x130F); все ITOC-секции (вкл. 0x11 FW_BOOT_CFG, 0x30 DBG_FW_INI)
  и остальные DTOC — без изменений.
- **Вывод: где link-type.** Применённый NV-override лежит в **DTOC 0xE6
  NV_DATA0, NV-журнал 0xFB0458..0xFB130F (slot B)**: записи TLV
  `nv_vpi_link_type` (id 0x12, mstflint-DB; LINK_TYPE = 2 бита,
  IB=0x1/ETH=0x2, offset 0x0.2); append-журнал — инвалидация старых записей
  (flag 0x80→0x00) + append нового поколения (meta 0x0b→0x07), две
  зоны-реплики 0x450/0x1240. **Image-defaults не менялись**
  (`[fw_boot_config]` = 0x11 FW_BOOT_CFG @0x43E9C8, slot A) — «default в
  образе» ≠ «applied override». Обоснование (hexdump обоих дампов,
  TLV-id в payload, исключение, PRS-контроль) — журнал §3.4.
- Находка для будущих исследований (вне скоупа фазы): формат NV-журнала
  NV_DATA0 зафиксирован эмпирически (запись 16B при len=4:
  flag/0x09/len/payload/crc4/meta4; CRC — FW-внутренний, не расшифрован);
  точная позиция 2-битового LINK_TYPE в 4B-payload не расшифрована
  (payload-мультимножество одинаково в ETH/IB-состояниях).
- ibstat (T1.3, как T1.2): port0 Active LID 16, port1 Active LID 13, оба
  Rate 40 QDR, SM lid 1, InfiniBand. Темп: max 63000 мК < 75000.
- `mstconfig q -e` (T1.3): LINK_TYPE_P1/P2 Default=Current=Next Boot
  `IB(1)` — override применён/стабилен.

### 1.4 Критерии главы 1 (спека §3)

- (a) T0-baseline полный (ri + raw + ab + dc + link-type) — **выполнен**
  (§1.1: ri md5, оба raw md5, ab, PRS, `LINK_TYPE_P1/P2` Default/Current
  обоих портов).
- (b) md5 host-rb == container-rb — **выполнен** (`a84545e5…` == `a84545e5…`;
  решение: raw — host mstflint).
- (c) port1 IB Active на Inviniscale-IV (LID + rate зафиксированы) —
  **выполнен** (Base lid 13, Rate 40 = QDR 4x, SM lid 1, Link layer
  InfiniBand; бонус — port0 тоже Active, LID 16).
- (d) PRS-дамп с активным IB + байтовый diff «где лежит настройка» —
  **выполнен** (PRS md5; diff 208 B → DTOC 0xE6 NV_DATA0, NV-журнал
  0xFB0458..0xFB130F; вывод — §1.3).

**Итог главы 1:** все критерии выполнены; карта на вендорном 4030-VPI в
IB-режиме (оба порта Active на фабрике, без burn); known-good-бэкап
`4030_eda_ri.bin` в `refs/`. Главы 2–4 (EN + E1-аналог; IB-образ →
финальное состояние; «мерж с приоритетами») — впереди, планы пишутся
под главу.

## 4. Глава 4 — E-rom + E-hwcfg эксперименты (live, EDA-карта)

Дата: 2026-09-12. План: `docs/superpowers/plans/2026-09-12-eda-ib-node-ch4.md`
(эрраты R4/R5). Журналы: `…/2026-09-12-eda-ib-node-ch4-task-01…04.md`.

### 4.1 T4.0 — 3 образа + офлайн-гейт (офлайн)

Журнал: `…/2026-09-12-eda-ib-node-ch4-task-01.md`.

| образ | состав | md5 (образ) |
|---|---|---|
| E-rom `build/xrom_1012cd_8008rom.bin` | база 1012-CDA + ITOC 0x18 ROM_CODE из 8008-ACA | `319868124f17ab34f747e1931a11bc31` (slot-A-половинка `2a5407048500cf3759b883fca8b00f46`) |
| control (дословно) | 8008-MCX512A-ADA | `1ea11b892e5951b31f1c99897a05a5e0` |
| test `build/xhw_8008ada_qsfphw.bin` | база 8008-ADA + ITOC 0x08/0x09 (HW_BOOT_CFG/HW_MAIN_CFG) из 4030-ri | `82a9689e5254cacdd473258e400d1c94` |

Входы (refs, md5): 1012-CDA `79d4ed9c338307507192b1aa4a8e9d67`; 8008-ACA
`7dce14844bb0aad995f9c4379836e0b7`; 8008-ADA `1ea11b892e5951b31f1c99897a05a5e0`
(== спеке); 4030-ri `27fb16c0a68311eacd8cfe6dad35f071`.

Офлайн-гейт (docs/550-poc/100-mlxfwutil/020-patch-matrix.md) — **PASS** по всем трём: `mlxfwutil.py verify`
(ITOC 25 + DTOC 7, all CRC OK) + `mstflint -i verify` («Image is
bootable») + `mstflint -i q` как ожидается (xrom: 16.35.1012 /
`MT_0000000013`, Rom 14.29.15/3.6.902; control и xhw: 16.35.8008 /
`MT_0000000361`); все ITOC-секции < 0x800000.

### 4.2 T4.1 — E-rom burn: ROM принят, mismatch = warning

Журнал: `…/2026-09-12-eda-ib-node-ch4-task-02.md`.

- pre: raw md5 `e91b6e72e5dc6a9c32e513cd9b0d48d1` (== `t22_post_raw` —
  флеш не менялась); `ab`: slot A erased (остатки T2.2), slot B intact
  1012-CDA (0013/rel-16_35_1012), valid = B.
- burn `-apc -y`: device-ID prompt дословно — `Image file ROM: FW is for
  device 4121, but Exp-ROM is for device 4119` → `-y`; `Restoring
  signature - OK`.
- post: 16.35.1012 / PSID `MT_0000000013`, Base GUID/MAC ≠ N/A,
  **Rom Info UEFI 14.29.15 / PXE 3.6.902 (от 8008; собственные у 1012-CDA
  14.28.15/3.6.804)**, dc/mstconfig OK, port0 100G ETH up (DAC), port1
  Down/Disabled (как pre-бейслин), темп 62000 мК.
- post raw `4c925c6b7c9a9032d1fef8436fddbdfd`; `ab`: slot A intact xrom
  (0013/rel-16_35_1012), slot B zeroed4 (контент 1012-CDA), valid = A.
- md5 post raw ≠ md5 build-образа (`31986812…`) — штатно: mstflint пишет
  ITOC-секции, не целую половинку (burn затрагивает только spans
  ITOC-секций — gap/старый слот не затрагиваются).
- **Вердикт: ROM (0x18 из 8008) на 1012-CDA-базе принят; device-ID
  mismatch (4121 vs 4119) = warning (логический), не блок.**

### 4.3 T4.2 — E-hwcfg control: burn OK → no-boot; FNP-recovery + MNVDA-фикс

Журнал: `…/2026-09-12-eda-ib-node-ch4-task-03.md`.

- pre: raw `4c925c6b…` == t41_post (цепочка OK); расхождение
  slot-A-половинки pre-ri — артефакт (см. §4.6), не аномалия
  (механизм верифицирован по mstflint-исходнику).
- burn 8008-ADA `-apc -y`: prompt version 16.35.1012→16.35.8008 + PSID
  0013→0361 (один блок) → `-y`; `Restoring signature - OK`.
- после reboot — **no-boot**: 81:00.0/1 отсутствуют в PCIe: 81:00.0 =
  AMD dummy fn `[1022:148a]` (+ 81:00.2 PTDMA `[1022:1498]`), `LnkSta
  DLActive-` (линк 16GT/s x16 поднят, endpoint не enum'ится), не FNP (нет
  `15b3:020d`), без AER, без netdev/hwmon/ibdev; reboot хоста (link
  retrain) не помог. **Порт-состояния не наблюдаемы** (control-бейслин
  не зафиксирован).
- FNP-recovery (владелец, docs/850-howto/100-cross-flash-ops §9.1): strap + power cycle →
  `15b3:020d` → raw-дамп мёртвого флеша → write-protect off → burn
  known-good 1012-CDA `-ocr -apc --nofs --ignore_dev_data -y` (→
  `Restoring signature - OK`) → `sg` GUID/MAC → strap off. Карта ожила
  (16.35.1012/0013, port0 100G up).
- Мёртвое T4.2 post-состояние: `dumps/t42_post_raw_fnp.bin` (md5
  `cff18c2f762806ededce4f977ee1e54c`): slot B = 8008-ADA
  (0361/rel-16_35_8008) intact — ITOC-область 0x0..0x50e177 побайтово ==
  вендорскому файлу; slot A = zeroed4 E-rom; valid = B.
- MNVDA-desync (docs/750-exp/140-post-fnp-guid-desync, CLOSED): после FNP-burn `q` → Base GUID/MAC = N/A
  (MNVDA GET рассинхронен; фактическая идентичность цела — netdev-MAC,
  sysfs/ibstat-GUID реальны). Фикс: `mlxfwutil.py guides` (1012-CDA →
  `guides_1012cda.bin`, md5 `c763d689eece0b3e6978e878fff4cd0d`) + burn
  `--nofs --ignore_dev_data -y` (рецепт docs/750-exp/140-post-fnp-guid-desync §8.8, без -apc/-ocr) →
  GUID/MAC видны в `q`; карта на baseline 1012-CDA.
- post (после фикса): raw `4a2f14d66f8c768724fd560b383c31d6`; `ab`:
  slot A zeroed4 (1012-CDA 0013/rel-16_35_1012), slot B intact
  guides-1012-CDA (0013/rel-16_35_1012), valid = B; темп 66000 мК.

### 4.4 T4.3 — E-hwcfg test (xhw): тоже no-boot ⇒ блокёр НЕ в 0x08/0x09

Журнал: `…/2026-09-12-eda-ib-node-ch4-task-04.md`.

- Short-circuit («T4.2 уже 100G up → T4.3 не нужен») — **не сработал**
  (T4.2 = no-boot).
- pre: raw `4a2f14d6…` == t42r_post (цепочка OK); ri slot-A-половинка
  `a0241b5a32a53e7c3b975bc20d85b4fc` == guides-половинке (активен slot B
  → padding 0xFF → совпадение валидно, см. §4.6).
- burn xhw `-apc -y`: prompt version 16.35.1012→16.35.8008 + PSID
  0013→0361 → `-y`; `Restoring signature - OK`.
- после reboot — **no-boot**, диагностика идентична T4.2 (dummy fn
  `[1022:148a]`, `DLActive-`, не FNP, без AER, без netdev/hwmon/ibdev;
  polling ~10 мин). Порт-состояния не наблюдаемы; post raw не получен
  (нет устройства) — ожидаемый `ab` (slot A valid xhw 0361/rel-16_35_8008,
  slot B zeroed4, valid = A) не верифицирован, восстановим raw-дапом в FNP.

Сравнение control↔test:

| образ | 0x08/0x09 | PSID | результат |
|---|---|---|---|
| T4.2 control (чистый 8008-ADA) | SFP28 2×25G (из 8008-ADA) | 0361 | no-boot |
| T4.3 test (8008-ADA + 4030-ri) | QSFP28 2×100G (из 4030-ri) | 0361 | no-boot |

Оба варианта HW-конфига → no-boot ⇒ **блокёр no-boot НЕ в 0x08/0x09**.

### 4.5 A/B-состояния по burn'ам главы

| этап | raw md5 | slot A @0x0 | slot B @0x800000 | valid |
|---|---|---|---|---|
| старт (t22_post == t41_pre) | `e91b6e72e5dc6a9c32e513cd9b0d48d1` | erased (остатки T2.2) | intact 1012-CDA (0013/rel-16_35_1012) | **B** |
| T4.1 post (xrom) | `4c925c6b7c9a9032d1fef8436fddbdfd` | intact xrom (0013/rel-16_35_1012) | zeroed4 (контент 1012-CDA) | **A** |
| T4.2 post (8008-ADA; мёртвый флэш, FNP-дамп) | `cff18c2f762806ededce4f977ee1e54c` (`t42_post_raw_fnp`) | zeroed4 (E-rom 0013/rel-16_35_1012) | intact 8008-ADA (0361/rel-16_35_8008) | **B** |
| FNP+guides (t42r_post) | `4a2f14d66f8c768724fd560b383c31d6` | zeroed4 (1012-CDA 0013/rel-16_35_1012) | intact guides-1012-CDA (0013/rel-16_35_1012) | **B** |
| T4.3 post (xhw) | не получен (no-boot, нет устройства) | не проверено — ожидаемо intact xhw (0361/rel-16_35_8008) | zeroed4 (guides-1012-CDA) — ожидаемо | ? (восстановимо FNP-дапом) |

### 4.6 Служебное: ri-дамп (артефакт сверки)

- `ri` (16MiB) = активный образ в slot-A-половинке (offset 0) + padding
  (fill) до 0x800000 + NV device data (0xf90000..0x1000000, MTCF) — как в
  raw; ДРУГОГО СЛОТА в ri-файле НЕТ (эта раскладка — у raw).
  Padding-область (конец последней ITOC-секции .. 0x800000; для layout
  1012-CDA/xrom — 2 813 416 B,
  0x800000 − 0x551218) = **0xFF при активном slot B, 0x00 при активном
  slot A** (механизм по mstflint-исходнику, журнал T4.2 Step 2:
  нулево-инициализированный буфер + `lastImageAddr` по физическому
  адресу конца последней ITOC-секции) ⇒ md5 «slot-A-половинки» ri
  зависит от активного слота — **артефакт сверки, не повреждение**
  (в T4.1 половинка ri совпала с build-половинкой именно так:
  0xFF == 0xFF).
- `mstflint -i <ri/raw> q/verify` **отказывается** от дамп, где
  valid-образ в slot B (slot A в файле zeroed/empty → «Invalid Image
  signature»); `mlxfwutil.py ab` декодирует оба слота — **ri-дампы сверять
  по slot-половинкам + `ab`** (по ITOC-секциям, не по md5 половинки).

### 4.7 Выводы главы 4

- **E-rom (T4.1):** ROM 0x18 из 8008 (UEFI 14.29.15 / PXE 3.6.902) на
  1012-CDA-базе принят; device-ID mismatch (4121 vs 4119) — warning,
  не блок. ROM миксуется (docs/550-poc/100-mlxfwutil/020-patch-matrix.md).
- **E-hwcfg (T4.2/T4.3):** образ 8008-ADA (MCX512A, x8 SFP28-board,
  PSID 0361) **не бутится на x16 QSFP28-100G-железе (15b3:1019) ни в
  одном варианте 0x08/0x09** (SFP28 из 8008-ADA и QSFP28 из 4030-ri —
  оба no-boot) ⇒ **блокёр no-boot НЕ в порт-HW-конфиге 0x08/0x09**.
  Гипотеза (**не верифицирована**): PCIe/board-конфиг внутри
  8008-ADA-образа (MCX512A x8/SFP28-board vs наше x16/QSFP28-железо).
  Вопрос «что определяет тип/рейт портов» главой 4 **не разрешён**
  (база не бутится — порт-состояния не наблюдаемы).
- Implication для главы 5: база 8008-CDAN (MCX546A, то же железо —
  0x1019, docs/250-re/100-formats/060-chip-map.md) этой несовместимости не имеет (ожидаемо).
- Критерии главы 4 (спека §6): (a) 3 образа + гейт — **выполнен**
  (T4.0); (b) E-rom — **выполнен** (T4.1: warning + Rom 14.29.15/3.6.902
  + карта OK); (c) E-hwcfg — **не выполнен в исходной формулировке**:
  порт-состояния не наблюдаемы (T4.2/T4.3 оба no-boot) — по эррате R5
  выводы записаны под фактические итоги; (d) выводы в docs/750-exp/120-eda-ib-node +
  docs/550-poc/100-mlxfwutil/020-patch-matrix.md — **выполнен** (эта секция); (e) карта не
  потеряна — raw/ab на каждом шаге, recovery-цепь в доступе.
- Recovery-цепь (known-good, refs): 1012-CDA / 8008-ADA / 8008-CDAN /
  4030-ri (+ build/xrom, guides-1012-CDA). Состояние карты на конец
  журналов главы: xhw (no-boot, post raw не получен); восстановление —
  владелец (FNP по чек-листу T4.2 / docs/850-howto/100-cross-flash-ops §9.1), T4.3 post-состояние
  восстановимо raw-дапом в FNP.

### 4.8 Разбор no-boot (офлайн-исследование, 2026-09-12)

Журнал: `docs/superpowers/journal/2026-09-12-ch4-no-boot-root-cause.md`
(полные таблицы/md5/byte-офсеты — там; здесь — выжимка).

**Сравнение с фазой Dell (docs/750-exp/110-dell-base-rework):** все PASS-миксы (E3-V3/V4, E4, E5)
прошивались на родное железо баз — MCX512A-ADA (S1, 41:00.0). E5 бутится
**с полностью чужим по железу INI** (ini 1012-EDA: QSFP28 2×100G Gen4
x16, VPI — на SFP28 x8 25G; `E5-0x30 == 1012-EDA-0x30` побайтово) ⇒
INI-несовпадение boot не блокирует. В ch4 8008-ADA-базы несли на другую
плату (MCX556A-EDA) — эту карту на 8008-коде никто не запускал.

**Board-дельта 8008-ADA ↔ 8008-CDAN** (одна релизия, разные платы,
`mlxfwutil.py diff`): ВСЕ кодовые секции (0x02–0x07, 0x0a–0x0c, 0x18 ROM)
**идентичны побайтово** ⇒ board-специфика в коде — **мёртвая гипотеза
(H1)**. Дельта плат — только конфиг:

| секция | Δ | ключевые поля |
|---|---|---|
| 0x08 | 3 B | 0x22–0x23 (`008f`→`030f`), 0xa0 |
| 0x09 | 114 B | port-блоки 0x241–0x2ab, PCIe-region 0x2c3–0x2eb (CDAN=0x00), width 0x343–0x3f3, speed-table 0x542–0x56d, PHY-tuning 0x86c (`35483548`→`8ca07c38`) |
| 0x11 | 4 B | 0x3c sub (`0120`→`0090`), 0x47 Gen3→Gen4 (`18`→`1a`), 0x1a8 |
| 0x12 | 11 B | 0x23, 0x2ab/0x2b7 speed mask (`0b`→`bb`), 0x39f width x8→x16 (`00`→`0a`), 0x782/0x89b/0x92b |
| 0x10/0x30/0xa0/0xe0 | — | идентичность (PSID/name/desc), ini, SIG_256, PSID-копия |
| boot-запись [0x100–0x10f] | 6 B | board-идентичность (ADA=`158054/67/9307`; CDA/CDAN/BCAN/EDA=`212084/27/860e`; для ch5 — правки нет, EDA==CDAN) |

Контроль: 4030-ri ↔ 1012-EDA (та же EDA-плата, 2 релизии): 0x08/0x09 —
**идентичны** (board-конфиг стабилен между релизиями); различия — только
release-поля (0x11 0x6/0xd, 0x12 0x18/0x72–0x7f, 0x10, 0x30, код).

**INI (0x30) — информативен, не функционален при boot:** E5 (выше);
рантайм читает бинарные 0x11/0x12, а не PRS-текст (docs/250-re/100-formats/067-prs-zlib.md, docs/250-re/130-cable-gate/015-speed-bits.md);
link-type default — 0x11, NV-override — DTOC 0xE6 (§1.3). «Забывшийся»
мерж INI в ch4 — **не причина** no-boot.

**Гипотезы (ранжировано):**
- **H3 (ведущая, не верифицирована):** board-профиль = 0x08+0x09+0x11+
  0x12+boot-запись+идентичность; xhw подменил только 0x08/0x09, 0x11/0x12
  остались ADA (Gen3 `0x47=18`, x8 `0x39f=00`, mask `0b`, sub `0120`,
  SR-IOV `a0`) — неконсистентный профиль для x16 QSFP28-100G-Gen4;
  control (чистый 8008-ADA) — консистентный, но чужой (MCX512A) профиль.
  Оба → no-boot с ранним PCIe-симптомом (endpoint не enum'ится).
- **H4 (вторая, не верифицирована):** сам 8008-код (main FW 16.35.8008)
  несовместим с MCX556A-EDA независимо от профиля: на карте 8008-код
  никогда не запускался (проверен только 8008-ROM в xrom); мерж кода
  между релизиями MCC-заблокирован (e1/T2.2) ⇒ H3/H4 не разделить без
  8008-CDAN-burn.
- H1 (board-код) — мёртва; H2 (INI) — отправлена (оба — выше).

**Решающие эксперименты (имена только; карта в FNP-восстановлении):**
1. **X0 (дискриминатор H3/H4):** чистый 8008-CDAN (`f5726f47…`)
   `-apc -y` — бутится ⇒ 8008 на железе OK, ch4 = ADA-профиль; no-boot ⇒
   H4 (8008-релизия несовместима с этой картой).
2. **X1:** 8008-ADA + 0x08/0x09/0x30 из 4030-ri (гипотеза владельца;
   ожид. no-boot — закрывает H2 live).
3. **X2:** 8008-ADA + полный board-дельта (0x08/0x09/0x11/0x12/0x10/
   0x30/0xa0/0xe0 + boot-запись) — max-test H3.

**Оценка базы главы 5 (8008-CDAN):** допустима, но **не «нативная»**
(формулировка спеки T5.1 не точна): CDAN — OCP-вариант («for OCP»,
no bracket; board-wiring/`pcie_tx_polarity`/`force_num_of_hosts` в ini),
board-дельта CDAN↔4030-ri: 0x08 2B (0x22 `03` vs `01`), 0x09 **80B**
(port-блоки, PCIe-region, PHY-tuning `8ca07c38` vs `62fc62fc`), 0x11 15B
(SR-IOV on `a0/08` vs `20/00`, EN `0x2b7=0a` vs VPI `07`, 0x1a8/0x2c0),
0x12 12B (0xf8 VPI `30` vs `31`, 0x223/0x263–0x26f/0x782/0x89b/0x92b).
Следствия для плана ch5: (a) **до мержей — X0** (чистый CDAN boot-test;
при no-boot — откат ch5 на 1012/4030-базу, xrom-рецепт); (b) T5.1
field-map расширить на 0x08/0x09/0x11/0x12 board-поля (не только
идентичность+VPI).

**Дополнение 2026-09-12 (инсайт владельца + верификация координатора):
OCP-подтверждение, X0 пересмотрен.**

Владелец: 8008-образы скачаны «не те» — из OCP-пакетов (другой
форм-фактор, инициализация PCI отличается). Офлайн-верификация:
поле `HW_BOOT_CFG (0x08) +0x22` = PCIe-topology/плата
(`0x00=x8, 0x01=x16 std, 0x03=OCP`; `mlxfwutil.py extract -s 0x08`,
значение кода — из журнала fs4-hashes, сверено по 5 образам):

| образ | 0x22 | ini-marker |
|---|---|---|
| 4030-ri (EDA-кросс-флеш владельца на подопытной, §4.9) | **0x01 (x16 std)** | = MCX556A-EDA |
| 1012-EDA (наш PN) | **0x01 (x16 std)** | «dual-port QSFP28; PCIe4.0 x16; tall bracket» |
| 8008-ADA | 0x00 (x8) | «25GbE dual-port SFP28; PCIe3.0/4.0 x8» |
| 8008-CDAN | **0x03 (OCP)** | «**for OCP** … no bracket» |
| 1012-EDAN | **0x03 (OCP)** | «**for OCP** … no bracket» |

**Вывод:** ВСЕ x16-образы релизии 8008 в refs — OCP-сборки
(0x22=0x03); нашей карте (std x16, 0x22=0x01) среди них нет.
Следствия:
- **X0 (чистый 8008-CDAN) — предсказуемый no-boot** (OCP-инит PCI на
  std-x16-слоте) → понизить до опционального datapoint.
- H3 **подтверждена на уровне полей** (поле существует, OCP ≠ std-x16;
  live-верификация остаётся).
- Новый дискриминатор (вместо X0): **X0' = 1012-EDA-база + 8008-код**
  (родной board-профиль с нуля: 0x22=0x01, Gen4, x16, VPI; рецепт —
  паттерн E5 из docs/750-exp/110-dell-base-rework «1012-база + 8008-код»; код побайтово идентичен
  во всех 8008-сборках ⇒ источник кода не важен) — бутится ⇒ H4 исключена,
  H3 подтверждена live, это старт ch5; no-boot ⇒ H4 (8008-код несовместим
  с чипом). Альтернатива: **non-OCP 8008 x16-образ** (скачать владельцу) →
  офлайн-сверка → burn.
- База ch5: (a) non-OCP 8008 x16 (если найден) или (b) **1012-EDA +
  8008-код** (все ингредиенты в refs; VPI-нативный; Dell-дельта из
  4030-ri).

### 4.9 Дополнение (2026-09-12, вечер): плата = ECA-T, родной 8008 найден

Уточнение владельца + офлайн-верификация координатора: стикер подопытной =
**MCX556A-ECAT** (base GUID — реестр `CARD_CX5_EDR100_GUID` = измеренный Node GUID;
MAC — реестр `CARD_CX5_EDR100_MAC`, суффикс подтверждён port GUID), и EDA 16.35.4030 в
«заводском» бэкапе `4030_eda_ri.bin` — **кросс-флеш владельца**, не
заводское состояние. Плата — **556A ECA** (Gen3 x16 std tall-bracket VPI,
PSID `MT_0000000008`, device_id `0x100f`); родные образы
**MCX556A-ECA 1012 + 8008** теперь в refs (`275fb8d3…` / `d80c5b31…`;
0x22=0x01, без «for OCP» в ini) — инвентаризация: `docs/050-hardware/100-inventory`, SKU: `docs/050-hardware/110-connectx5-sku`.

Следствия:
- Урок ch4 «все 8008-x16 в refs — OCP» **ревизован**: 8008-ECA — std.
  no-boot T4.2/T4.3 — x8-профиль (`0x22`=0x00) на x16-карте (оба варианта
  8008-ADA); x16-std-профили (CDA 1012, EDA 4030/1012) грузятся.
- Новый главный эксперимент **X0'' = бёрн 8008-ECA** (родный образ платы:
  родной board-профиль + 8008-код; `-apc -y`, PSID 0009→0008, device_id
  0x1019→0x100f — ожидаемо): бутится ⇒ H4 исключена (8008-код OK на этом
  кремнии), 8008-ECA = база ch5; no-boot ⇒ H4 (8008-код несовместим с
  кремнием) — решение владельца по цели «8008-код». X0 (CDAN, OCP) и X0'
  (1012-EDA + 8008-код) — понижены до фоновых.
- FNP (владелец, идёт): вместо staged 1012-CDA допустим **1012-ECA**
  (родной образ, PSID 0008) — CDA тоже работает (доказано ch2), ECA
  «нативнее»; после ECA-бёрна card = родное состояние платы.

### 4.10 FNP-рекавери завершён (владелец, 2026-09-12) + офлайн-верификация 8008-ECA

Лог владельца: `refs/fw/cx-5-6/dumps/fnp-log-2026-09-12-eca-recovery.txt`.

**Последовательность (из лога):**
1. `mstflint -d 81:0.0 rb 0x0 0x1000000 /var/roothome/x0_fnp_dead_raw.bin`
   — сырой думп трупа (xhw-состояние). Архив:
   `refs/fw/cx-5-6/dumps/x0_fnp_dead_raw.bin` (md5
   `ae7b2c617993d5fb4c449652ef4336eb`). Верификация: IMAGE_INFO =
   **PSID `MT_0000000361`, name `MCX512A-ADA_Ax_Bx`, PRS
   `cx5_MCX512A_2p_x8_25g_hb.prs`** — xhw, как и ожидалось (8008-ADA-база,
   x8-профиль).
2. `mstflint -d 81:0.0 -i guides_1012eca.bin -apc -y
   --ignore_dev_data --nofs b` — бёрн образа
   `guides_1012eca.bin` (md5 `29f0e62c9b83142a518ba10c4212ac9d`,
   архив `refs/fw/cx-5-6/dumps/guides_1012eca.bin`) = **1012-ECA +
   guides (тулка mlxfwutil)**: IMAGE_INFO побайтово = референсному
   1012-ECA (`275fb8d3…`); промпты: 16.35.8008/`0361` → 16.35.1012/`0008`;
   «Restoring signature - OK».
3. Cold boot. Пост-состояние (live, из лога):
   - `lspci`: **81:00.0/81:00.1 `[15b3:1017]` Infiniband controller**
     (карта жива, VPI-дефолт = IB-режим; до — `[15b3:1019]` ETH на EDA);
   - `mstflint q`: FW **16.35.1012**, PSID **`MT_0000000008`**,
     Base GUID **реестр `CARD_CX5_EDR100_GUID` (8)**, Base MAC **реестр `CARD_CX5_EDR100_MAC` (8)**
     — = значения со стикера (docs/050-hardware/100-inventory);
   - `dc`: name `MCX556A-ECA_Ax`, «ConnectX-5 VPI adapter card; EDR IB
     (100Gb/s) and 100GbE; dual-port QSFP28; **PCIe3.0 x16**; tall
     bracket».

**Офлайн-верификация 8008-ECA (`d80c5b31…`), подготовка к X0'':**
- `0x08 HW_BOOT_CFG +0x22/0x23 = 0x01/0x07` — x16 std, Gen3 (родной
  профиль платы; «for OCP» в ini нет).
- `diff 1012-ECA ↔ 8008-ECA`: **0x08 и 0x09 — идентичны** (board-профиль
  стабилен между релизиями, как в паре 4030↔1012-EDA); различия — только
  кодовые секции (IRON_PREP/MAIN_CODE/PCI_CODE/UPGRADE_CODE/PCIE_LINK 4B/
  ROM_CODE), 0x10 (33B версия/идентичность), 0x11 (8B), 0x12 (10B), 0x30
  ini, SIG_256. Т.е. 8008-ECA = ровно «1012-ECA-база + 8008-код», который
  вендор собрал сам.

**Коррекция ожидаемых промптов X0'' (к §4.9):** старт уже не «0009/0x1019»,
а текущее состояние 1012-ECA: **PSID `0008` → `0008` (промпта PSID не
будет)**, версия 1012 → 8008 (новее — промпта downgrade не будет),
device_id сейчас **`0x1017`** (live; ожид. `0x1017` и после 8008-ECA в
IB-режиме; «0x100f» из docs/050-hardware/100-inventory — непроверенное ожидание, live 1012-ECA
пишет `0x1017`).

## 5. Глава 5 — E-code: 8008-ECA + Gen4 + порт-конфиг (live, ECA-карта)

План: `docs/superpowers/plans/2026-09-12-eda-ib-node-ch5.md` (с эрратами).
Журналы: `docs/superpowers/journal/2026-09-12-eda-ib-node-ch5-task-01…05.md`
(task-04b — чистый повтор T5.3; task-04 — superseded). Даты: live
2026-09-12, RDMA-аддендум 2026-09-13.

Карта: `81:00.0`/`81:00.1`, `15b3:1017`, MCX556A-ECAT (GUID/MAC — реестр
`CARD_CX5_EDR100`/docs/050-hardware/100-inventory). Обвязка (владелец): port0
(P1, 81:00.0) — 100G ETH-свитч (SN 2700, DAC); port1 (P2, 81:00.1) —
Inviniscale-IV (QDR-фабрика).

### 5.1 Эрраты к спеке §7 (верифицировано)

| спека §7 (2026-09-10) | факт (2026-09-12) | причина |
|---|---|---|
| база = 8008-CDAN + Dell-дельта | база = **8008-ECA** (нативный образ платы) | 8008-CDAN = OCP (`0x08+0x22`=0x03); карта — std x16 (0x01); все 8008-x16 в refs — OCP, кроме полученного нативного 8008-ECA (§4.8–4.9, docs/050-hardware/100-inventory) |
| Dell-идентичность (PSID `0009`, sub `0002`, device `0x1019`) | **нативная ECA** (PSID `0008`, device `0x1017`) | «заводской» `4030_eda_ri.bin` = кросс-флеш владельца (EDA-образ на ECA-плате), не Dell-заводское (docs/050-hardware/100-inventory, уточнение владельца) |
| T5.1 field-map = 4030-ri ↔ 8008-CDAN | field-map = **Gen4 (4 поля) + port0-ETH (1 байт)** | 8008-ECA нативно = VPI 2×100G QSFP28 x16; дельта до финала только Gen4 + порт-конфиг (diff 2026-09-12) |
| T5.3 — один финальный burn | **2 шага:** T5.2 (Gen4) → T5.3 (+port0 ETH) | изоляция диагностики; «по нарастающей» (владелец) |
| — | добавлен **T5.0 = X0''** (официальный 8008-ECA verbatim) | дискриминатор H4 (8008-код на кремнии) до любых мержей (§4.9) |
| §8: «15b3:1019» | `15b3:1017` | ECA non-Ex (docs/050-hardware/100-inventory) |
| T5.3 — финальный burn | **чистый повтор (task-04b)**: guides-образ t53 + burn `--ignore_dev_data --nofs` | первое исполнение загрязнено: интервенция владельца (кабель → ручной `mstconfig set LINK_TYPE_P1=ETH` + перегруз FW) + нереальная строка mstconfig в журнале task-04 (2026-09-12) |

### 5.2 T5.0 — X0'': официальный 8008-ECA verbatim (live)

Журнал: `…-ch5-task-01.md`.

- Pre: 1012-ECA + guides (recovery §4.10): raw `3e4b334284c5a2fa3b0629fdb7e751ef`,
  ri `6a435377730c94cff88e2025ab1dbf3a`.
- Burn `8008eca.bin` (md5 `d80c5b311ff85b9d0260b5b079a9a21a`) `-apc -y`:
  промптов нет (PSID `0008`→`0008`; 1012→8008 — новее),
  `Restoring signature - OK`.
- Post: boot (BOOT, **PASS**) — 16.35.8008 / `MT_0000000008`, GUID/MAC без
  изменений, `dc`: `MCX556A-ECA_Ax` (VPI, PCIe3.0 x16).
- **H4 ИСКЛЮЧЕНА** — 8008-код на этом кремнии (MT27800/`0x1017`,
  MCX556A-ECAT) стартует штатно.
- LnkSta `8GT/s x16` (Gen3 — нативный профиль ECA-образа; baseline для T5.2).
- Post raw: `6faac68bd836b174463a04778519e3bd` (16MiB).
- Отклонение (зафиксировано): параллельный старт `rb`+`ri` →
  `MFE_SEM_LOCKED` — гонка за flash-semaphore, не карта; повтор
  последовательно (ch4-паттерн).

### 5.3 T5.1 — field-map + сборка t52_g4/t53_final (офлайн)

Журнал: `…-ch5-task-02.md`.

Field-map (каждое поле дельты учтено — completeness):

| поле | сейчас (8008-ECA) | цель | в t52 | в t53 | обоснование |
|---|---|---|---|---|---|
| `0x08+0x23` | `07` | `0f` | ✓ | ✓ | max PCIe speed Gen3→Gen4 (docs/750-exp/110-dell-base-rework; docs/750-exp/160-hpe-cx5-vpi-gen4-precheck §5.3) |
| `0x09+0x86c..f` | `4d3a4d3a` | `62fc62fc` | ✓ | ✓ | Gen4 PHY-tuning (docs/750-exp/110-dell-base-rework {CDA,EDA}=62fc62fc; `cx5_gen4_enable.py` патчит 0x86C..F) |
| `0x11+0x47` | `18` | `1a` | ✓ | ✓ | Gen4 x16 (docs/750-exp/110-dell-base-rework) |
| `0x11+0x93` | `45` | `47` | ✓ | ✓ | PCIe cap_index Gen3→Gen4 (docs/750-exp/160-hpe-cx5-vpi-gen4-precheck; docs/550-poc/100-mlxfwutil/020-patch-matrix.md) |
| `0x11+0x2b7` | `07` | `03` | ✗ | ✓ | port0 (P1) vpi link-type: VPI def-IB → ib+eth def-ETH (docs/750-exp/110-dell-base-rework decode) |
| `0x11+0x2bb` | `07` | `07` | ✗ | ✗ | port1 (P2) = IB (не менять) |
| `0x11+0x2d/0x3d` | `17`/sub | keep | ✗ | ✗ | device/sub — нативная ECA-идентичность |
| `0x12` (весь) | — | keep | ✗ | ✗ | 1012-ECA↔EDA идентичны — Gen4-полей нет |
| 0x10/0x30/SIG (релизные) | — | keep | ✗ | ✗ | идентичность/артефакты сборки; рантайм читает бинарные (docs/250-re/100-formats/067-prs-zlib.md) |

Сборка + офлайн-гейт (**PASS**):

- `t52_g4.bin` = 8008-ECA + Gen4 (4 поля): md5 **`cee795cb06896702b427030d4b3745a7`** (X);
- `t53_final.bin` = t52 + `0x11+0x2b7=03`: md5 **`5e15694311f6bbad85734cb52caf33ce`** (Y);
- verify: PASS ×2 (ITOC 25 + DTOC 7, all CRC OK);
- diff: E8008 vs t52 — ровно 7 B (4 поля), t52 vs t53 — ровно 1 B; лишних
  байтов нет;
- no-op merge (кодовые секции 8008-ADA → 8008-ECA-база) — побайто идентичен
  (NOOP_IDENTICAL): кодовые секции 8008-ADA ↔ 8008-ECA идентичны.

Репродукция: `tests/test_mlxfwutil.py` (`TestCh5EcodeMergeRepro`): t52/t53
пересобираются из 8008-ECA + field-map (in-memory + CLI в tmp dir) →
md5 == X/Y; no-op merge == база.

### 5.4 T5.2 — Gen4 burn (live)

Журнал: `…-ch5-task-03.md`.

- Pre: raw `6faac68bd836…` == `t50_post_raw` (карта не менялась с T5.0).
- Burn `t52_g4.bin` `-apc -y` → `Restoring signature - OK`; reboot.
- **Критерий: LnkSta 8GT/s → 16GT/s x16 (Gen4) — PASS.**
- Оба порта по-прежнему IB (image-default): port1 (P2) `Active/LinkUp`
  на fabric (LID 13, SM 1), port0 (P1) `Down/Polling` — IB-порт против
  ETH-пиров (t52 держит оба в IB; port0 def-ETH — t53).
- Post raw: `2d3c5cef3a5dabd5210ade94bb9d9248`; A/B: A zeroed4 / B valid (t52).
- Побайто: flash slot B == t52 (FW-регион 0 diff), все 4 Gen4-поля на
  флэше (таблица в журнале Step 6); отклонения — только штатные
  артефакты burn.

### 5.5 T5.3 — порт-конфиг: port0 ETH / port1 IB (live)

Первое исполнение (журнал `…-ch5-task-04.md`) — **НЕВАЛИДНО,
superseded**: интервенция владельца (кабель → ручной
`mstconfig set LINK_TYPE_P1=ETH` + перегруз FW) + нереальная строка
mstconfig в журнале (корректировка — там же, коммит `af1175a`).

Чистый повтор (task-04b, журнал `…-ch5-task-04b.md`):

- guides-образ `t53g.bin` = t53_final + родные GUID/MAC: md5
  **`1fd5c1bb58bf0e69013373a45cf39da2`** (Z); verify ×2 (mlxfwutil +
  mstflint), diff = только device-data (DEV_INFO/MFG_INFO).
- Burn `--ignore_dev_data --nofs -y` (без `-apc` — PSID `0008`→`0008`) →
  `Restoring signature - OK`.
- **`--ignore_dev_data` СТЁР старый NV-override**: POST-BURN P1 `0/0/0` без
  `*` (image-default), P2 `IB(1)/IB(1)/IB(1)` — окно наблюдения не
  загрязнено.
- Окно наблюдения ~21 мин без интервенций (11 поллов): port0 = ETH-функция
  (PCIe-класс Ethernet, ibstat Ethernet, QSFP28-модуль опознан), но
  speed-конфиг = `1000baseKX/Full` only → ни одного link-события.
- **Вердикт (ветка 2): байт `0x11+0x2b7=03` (def-ETH) сам по себе
  НЕДОСТАТОЧЕН** — ставит только link layer; требуется NV-override
  `LINK_TYPE_P1=ETH(2)` (паттерн docs/750-exp/160-hpe-cx5-vpi-gen4-precheck: у HPE VPI-карты он в NV).
- Фикс (по плану): `mstconfig -d 81:00.0 -y set LINK_TYPE_P1=ETH` (t-adm) +
  reboot → **100G up за ~13 c, стабилен** (`Speed: 100000Mb/s, Full`;
  >13 мин без новых link-событий).
- POST-FIX mstconfig: `* LINK_TYPE_P1  0  ETH(2)  ETH(2)`; P2
  `IB(1)/IB(1)/IB(1)`.
- Post raw: `7760dab70b074da6f5186ea70d4dee18`; A/B: A zeroed4 / B valid
  (t53g); патч-поля + GUID/MAC на флэше (Step 7).

mstconfig-доступ (факт task-04b): t-adm — `mstconfig -e -d 81:0.0 q`
(`-e` ПЕРЕД подкомандой → 3 колонки Default/Current/Next Boot; без `-e` —
одна колонка); toolbx владельца — 3 колонки; шелл координатора — нет PCI;
сервер — нет `mlxconfig_host.db`.

Пост-главный эксперимент (владелец, live 2026-09-13, лог
`refs/fw/cx-5-6/mstconfig-reset-2026-09-13.log`): `mstconfig -y reset` +
reboot → P1 `0 0 0` (без `*`), P2 `IB(1) IB(1) IB(1)`; port0 advertise'ит
**полный 100G-набор** (KR4/SR4/CR4/LR4_ER4 + 25/40/50G) — НЕ
1000baseKX-only (противоречит наблюдению этого раздела при том же P1=0 /
том же флэше), но линк не поднимается ни с DAC («Unsupported cable»), ни с
оптикой. (Резолюция — абзац ниже: корневая причина — перекодировка байта
0x03.)

**Резолюция (эксперимент t53h, владелец, live 2026-09-13, лог
`refs/fw/cx-5-6/t53h-2026-09-13.log`):** корневая причина «байт 0x03
недостаточен» — **перекодировка**: `0x03` — это не «def-ETH», а «ib+eth,
без default» (биты {b0=net_ib, b1=net_eth, b2=def_ib, b3=def_eth};
сверено со всеми 7 лестничными образами: EN-карты 8008/1012 ADA/ACA/CDA =
**0x0a**, VPI-карты 8008-ECA/1012-EDA/ECU/4030-HPE = **0x07**, `0x03` ни у
одной; ini HPE: `vpi.{network,default}_link_type_{ib,eth}`). `t53h = t53g +
0x11+0x2b7=0a` (md5 **`2b8d6e16d61a54cae712fd84fc5f0370`**, diff = 1 байт,
port1 `0x2bb=07` не тронут): burn `--ignore_dev_data --nofs -y` (стирает
NV-override) + reboot → **port0 = 100G ETH up (DAC) БЕЗ NV-override и БЕЗ
mstconfig** (`Speed: 100000Mb/s, Lanes 4, Full, Link detected: yes`);
`mstconfig -e q`: строки `LINK_TYPE_P1` **НЕТ вообще** (порт EN-locked, не
VPI-выбираемый), P2 `IB(1) IB(1) IB(1)`; ibstat: port0 Ethernet Active
Rate 100, port1 **IB Active Rate 40, LID 13** (не тронут); `q`: 16.35.8008 /
`MT_0000000008`, GUID/MAC == стикеру. **Финальный рецепт: `0x0a` в образе;
mstconfig выбывает из рецепта.** Паттерн HPE (0x07 + NV `ETH(2)`) остаётся
вендорным VPI-путём для 0x07-байта.

**Дополнение «оставить выбор» (t53i, владелец, live 2026-09-13, лог
`refs/fw/cx-5-6/t53i-2026-09-13.log`):** вопрос владельца — можно ли
прошить так, чтобы порт оставался выбираемым (VPI), а не EN-лок. Ответ:
**0x0b** (VPI def-ETH: {net_ib=1, net_eth=1, def_eth=1} — то, что
означал «def-ETH» до перекодировки 0x03). `t53i = t53h + 0x2b7: 0a→0b`
(md5 **`e86aef8092aba27728f42d21aa0952ff`**, diff = 1 байт): burn
`--ignore_dev_data --nofs -y` + reboot → **port0 100G (DAC) по умолчанию,
без NV**; `mstconfig -e q`: `LINK_TYPE_P1 = ETH(2) ETH(2) ETH(2)` **без
`*`** — колонка Default теперь **`ETH(2)`** (image-default из бита
def_eth; у 0x07/0x03 было `0`), P2 `IB(1)×3`; ibstat: port0 Ethernet
Active Rate 100, port1 IB Active Rate 40 LID 13 (не тронут). Выбор
сохранён: `set LINK_TYPE_P1=IB` переключает port0 в IB (NV). **Settable
значения на CX-5 — только {IB(1), ETH(2)}**: `set LINK_TYPE_P1=VPI` / `=3`
/ `=0` → `-E- Unknown value` (VPI(3) как set-значение — CX-2/3-паттерн по
знанию владельца; гипотеза владельца: это может быть причиной
неработающего «device_default(0)», а «numeric vs enum» — самостоятельный
инструментальный вопрос mstconfig). **Текущее состояние карты: t53i**
(VPI def-ETH); t53h (EN-лок) — альтернатива. Raw-дамп t53h-состояния
`dumps/t53h_final_raw.bin` md5 `5f05971947cc29fe8d6bb4a3bdb07d72` —
**верифицирован побайто** (payload [0x0..0x510000) + DTOC: 0 diff vs
`build/t53h.bin`; слот A valid, B zeroed4; padding — blank-представление
0x00 vs 0xFF).

### 5.6 T5.4 — финальное состояние: IB-узел (live, read-only)

Журнал: `…-ch5-task-05.md` (+ аддендум 2026-09-13 02:41).

- port1 (P2, `mlx5_3`, 81:00.1): **IB Active/LinkUp, Rate 40 (QDR 4x),
  Base LID 13, SM lid 1**; ibnodes: CA (реестр `CARD_CX5_EDR100_P1_GUID`) виден
  (Infiniscale-IV, 36 портов, LID 5; SM — `master ibp1s0`, LID 1). Rate 20
  сразу после reboot — транзиент SM discovery, улегся сам за ~60–90 c.
- RDMA (аддендум, по указанию владельца): `ib_write_bw` (t-adm) RC
  65536B × 5000: `ib_write_bw -F -d mlx5_3 -i 1 <ipoib peer — реестр `HOST_MASTER_IPOIB_IP`>` —
  **3729.16 MiB/s avg ≈ 31.2 Gb/s = полный QDR-рейт** (канон docs/750-exp/160-hpe-cx5-vpi-gen4-precheck:
  31.28 Gb/s), LID 13 ↔ 4. Первоначальный §12.6-fallback («без бенча»)
  снят: perftest-контрольный канал — OOB-Ethernet (подсеть — реестр
  `HOST_MASTER_IPOIB_NET`)
  («Data ex. method: Ethernet»), ssh/podman-доступа на peer не требуется.
- port0 (P1, `mlx5_2`, 81:00.0): **100G ETH up** — ethtool
  `100000Mb/s, Full, Link detected: yes` (SN 2700).
- Gen4: LnkSta `16GT/s x16`.
- mstconfig: `* LINK_TYPE_P1  0  ETH(2)  ETH(2)` /
  `LINK_TYPE_P2  IB(1)  IB(1)  IB(1)`; `q`: 16.35.8008 / `MT_0000000008`,
  GUID/MAC == родным; `dc`: `MCX556A-ECA_Ax` VPI.
- Финальный raw `t54_final_raw.bin` md5
  **`7760dab70b074da6f5186ea70d4dee18`** (== `t53b_post_raw` — флеш не
  менялся с task-04b); `ab`: valid slots = B (t53g), A zeroed4; delta vs
  t53g = только NV-журнал (MTCF, TLV `nv_vpi_link_type` id 0x12) +
  blank-представление.
- **Вердикт: PASS — IB-узел готов** (критерии спеки (d)–(e) все
  выполнены; аномалий нет, откат не потребовался).

Post-chapter update (2026-09-13, ad-hoc t53h/t53i — §5.5): финальное
состояние достигается **без NV-override**: `build/t53h.bin` (0x2b7=0a,
EN-лок) или **`build/t53i.bin` (0x2b7=0b, VPI def-ETH — текущее
состояние карты, выбор IB/ETH сохранён через NV)**. port1 IB идентичен в
обеих (байт `0x2bb=07`, LID 13, QDR) — RDMA-результат §5.6 остаётся в силе
(конфигурация port1 не менялась). mstconfig (t53i): `LINK_TYPE_P1 =
ETH(2) ETH(2) ETH(2)` без `*` (Default = image-ETH) / P2 `IB(1)×3`.
Raw-дампы (оба верифицированы побайто, `ab` + python-сравнение):
t53h-состояния — `dumps/t53h_final_raw.bin` md5 `5f05971947cc29fe8d6bb4a3bdb07d72`
(valid = A); t53i-состояния — `dumps/t53i_final_raw.bin` md5
`970636c62e1fbf24cfe706a43680bf00` (valid = B, payload
[0x800000..0xD10000) 0 diff vs `build/t53i.bin`; DTOC-регион общий для
обоих слотов — 0 diff в обоих дампах). Факт A/B-механизма: «zeroed4» —
нулируются только 4 байта magic (старый payload в невалидном слоте
остаётся: slot A = t53h-контент минус 4 magic-байта); burn
ротировал активный слот A→B.

### 5.7 A/B-таблица по ВСЕМ burn'ам фазы (ch2–ch5)

Значения — из журналов/док: E-ladder — docs/750-exp/110-dell-base-rework §2 (01:00.x); EDA ch2 —
спека §2.2 (81:00.0); ch4 — §4.5 (81:00.0); ch5 — журналы task-01…05
(81:00.0).

**E-ladder (Dell-фаза, 01:00.x, MCX512A 2×25 SFP28) — docs/750-exp/110-dell-base-rework §2:**

| шаг | образ (md5) | вердикт | состояние портов |
|---|---|---|---|
| E0 | 1012-ADA `cd95e4fe…` | PASS | port0 UP 25G |
| E1 | — (mixed-CODE) | SKIPPED: MCC digest-reject | — (отклонённый burn записал ~4.3MiB в slot A) |
| E2 | 8008-512F `3a053d03…` | BOOT PASS / LINK DOWN | 1G-KX-образ, линк DOWN |
| E3-V1 | 8008-ADA `1ea11b89…` | PASS | port0 UP 25G |
| E3-V2 | 8008-ACA `7dce1484…` | PASS | port0 UP 25G |
| E3-V3 | ADA+ROM(ACA) `16e099da…` | PASS (mixed ROM; ~~не blocked~~ — см. поправку ниже) | port0 UP 25G |
| E3-V4 | ACA+ROM(ADA) `4d6c96a3…` | PASS (mixed ROM; ~~не blocked~~ — см. поправку ниже) | port0 UP 25G |
| E4 | build/e4 `cd95e4fe…` (== 1012-ADA) | PASS (canary) | port0 UP 25G |
| E5 | build/e5 `e5b03e52…` (PSID 0009 + IB-поля) | PASS: class [0207] IB, PCIe 16GT/s x8 | IB-порт DOWN (физ. 25G-свитч, нет фабрики) |
| T15 | 1012-ADA `cd95e4fe…` (FNP-restore) | PASS (restore) | port0 UP 25G, родные GUID/MAC |

**Поправка к E-ladder (2026-10-28, цикл burn-digest):** интерпретация
«mixed ROM — не blocked» (дigest-гейт якобы покрывает код, но не ROM) —
**ОПРОВЕРГНУТА**: E3-V3/V4, E4, E5 шли `plain + -apc` →
`_mccSupported=false` (flint/subcommands.cpp:2590-2594) → прямой
flash-путь, digest-гейт FW не выполнялся вовсе. Гейт = безусловный
content-digest всего образа (секционной дискриминации нет); E1/T2.2
ловили reject только потому, что шли plain без `-apc` (совпадающий PSID
→ MCC-путь). Реаттрибуция и численные свертки —
`docs/superpowers/reports/2026-10-28-burn-digest-gate-results.md` §4;
поправки на месте — docs/750-exp/110-dell-base-rework §0/§2.

**EDA ch2 (81:00.0, 2026-09-10/11) — спека §2.2:**

| шаг | образ (md5) | вердикт | состояние портов |
|---|---|---|---|
| T2.1 | 1012-CDA `79d4ed9c338307507192b1aa4a8e9d67` | PASS (known-good EN) | port0 100G ETH (DAC) up; slot B |
| T2.2 | E1-аналог `008844a71ebf04b8983fc8b31dabce65` | MCC-reject (digest) — воспроизведено | карта на 1012-CDA (slot B); отклонённый burn записал 4 406 051 B в slot A |

**ch4 (81:00.0, 2026-09-12) — §4.5:**

| шаг | образ (md5) | вердикт | состояние портов |
|---|---|---|---|
| T4.1 | xrom (1012-CDA + 8008 ROM) `319868124f17ab34f747e1931a11bc31` | PASS: ROM принят, mismatch = warning | port0 100G ETH (DAC) |
| T4.2 | 8008-ADA `1ea11b892e5951b31f1c99897a05a5e0` | **no-boot** (x8-профиль на x16-карте) | не наблюдаемо (FNP-дамп) |
| T4.3 | xhw (8008-ADA + 4030-ri 0x08/0x09) `82a9689e5254cacdd473258e400d1c94` | **no-boot** — блокёр НЕ в 0x08/0x09 | не наблюдаемо |
| FNP | guides_1012eca `29f0e62c9b83142a518ba10c4212ac9d` | PASS: карта жива | IB-режим `0x1017`, 1012-ECA + guides (§4.10) |

**ch5 (81:00.0, 2026-09-12/13):**

| шаг | образ (md5) | вердикт | состояние портов |
|---|---|---|---|
| T5.0 | 8008-ECA `d80c5b311ff85b9d0260b5b079a9a21a` | PASS (H4 исключена) | оба IB (image-default); Gen3 8GT/s x16 |
| T5.2 | t52_g4 `cee795cb06896702b427030d4b3745a7` | PASS: Gen4 16GT/s x16 | оба IB: port1 Active (LID 13), port0 Down/Polling |
| T5.3-первое | t53_final `5e15694311f6bbad85734cb52caf33ce` | **невалидно** (superseded) | интервенция владельца (кабель + ручной NV set) |
| T5.3b | t53g `1fd5c1bb58bf0e69013373a45cf39da2` (+ NV `LINK_TYPE_P1=ETH(2)`) | PASS: байт `0x03` сам по себе недостаточен — NV-override обязателен | port0 100G ETH up (~13 c после фикса), port1 IB |
| T5.4 | (без burn) final raw `7760dab70b074da6f5186ea70d4dee18` | **PASS: IB-узел готов** | port0 100G ETH + port1 IB Active QDR (LID 13, Rate 40, ib_write_bw 31.2 Gb/s) + Gen4 x16 |
| T5.3c (ad-hoc) | t53h `2b8d6e16d61a54cae712fd84fc5f0370` (`0x2b7=0x0a`, без NV) | **PASS: `0x0a` достаточен** (0x03 — перекодировка) | port0 100G ETH (DAC, без mstconfig), port1 IB Active QDR (LID 13) |
| T5.3d (ad-hoc) | t53i `e86aef8092aba27728f42d21aa0952ff` (`0x2b7=0x0b`, VPI def-ETH, без NV) | **PASS: выбор сохранён** — 100G по умолчанию + NV-переключение | port0 100G ETH (DAC, по умолчанию, Default=ETH(2) в mstconfig), port1 IB Active QDR (LID 13) — **текущее состояние** |
