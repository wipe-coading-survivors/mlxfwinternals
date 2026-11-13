# 150-cx6dx-enib-root

**Статус:** seed
**Цель:** идея (владелец): при успехе полного рута CX-5 (исполнение кода на
стеке) — распространить конвейер на CX-6 Dx; вендорские SKU поколения —
CX-6 Dx (EN-only) или «ConnectX-6 DE» (IB-only), но это один чип/бинарник.
Трек ведём независимо от CX-5: обе Dx-карты (secure FB и non-secure CDAT)
на руках.
**Критерии закрытия:** EN-карта CX-6 Dx переведена в IB (линк + рейт
зафиксированы) и/или исполнение своего кода на iRISC Dx воспроизведено;
карты не потеряны.
**Фазы/задачи:** (офлайн-задел уже есть — см. тело: побайтовая идентичность
CDA↔HDA, карта дельты ~117 Б, VPI-байт `0x11+0x2df`, IB-биты-кандидат)
- [ ] зафиксировать офлайн-факты (CDA↔HDA: один бинарник, карта дельты) в
      нумерованный док — номер согласовать с владельцем
- [ ] приезд карты: read-only чек — `lspci -nnd 15b3:` (ждём `15b3:101d`),
      `mstflint q` (PSID → сток-образ с firmware-страницы; **Security
      Attributes: N/A**; GUID/MAC = стикеру — значения замерим при приезде
      карты, до измерения не фиксируются); known-good = сток-образ (без `ri`-бэкапа —
      `no-fw-backup`)
- [ ] field-map: сток карты ↔ HDA-903 (`mlxfwutil diff`), дельта по полям —
      методология `docs/850-howto/120-field-merge` (identity оставляем свою; port-count совпадает —
      обе single-port)
- [ ] сборка: сток + IB-дельта из 903 (~117 Б) + VPI-байт `0x11+0x2df` +
      `guides`; офлайн-гейт → burn (non-SB → legacy-flow) → IB-линк.
      Гипотеза: HDR-рейт на «100G»-SKU (код/PHY/PROG_HW_FW идентичны;
      worst case — EDR-рейт/no-link, откат по known-good (сток-образ))
- [ ] рут-трек: boot-patch на 22.50 MAIN_CODE — точку инъекции искать
      заново (MAIN_CODE другой; метод доказан на CX-5 — `docs/250-re/120-irisc/025-boot-injection.md`)
**Семёна:** ROADMAP-секция «CX-6 Dx: EN→IB + рут» (поднято 2026-09-26;
перенесена целиком); офлайн-задел — проект cx6dx-bazzite + циклы
cx6dx-securefw / cx6dx-introspection (C3-вердикт).
**Связи:** `docs/250-re/110-signing/055-cx6dx-signing.md`,
`docs/superpowers/reports/2026-10-31-cx6dx-introspection.md`, `docs/850-howto/120-field-merge`
(методология field-map), `docs/250-re/120-irisc/025-boot-injection.md` (метод рута CX-5), `docs/050-hardware/100-inventory`,
`docs/850-howto/100-cross-flash-ops` (burn-флаги), `TODO.md` (раздел «BlueField-карты:
исследования»); journal `2026-09-17-cx6dx-bazzite-ib-task-01.md`
(IB-биты-задел, task-01 Step 5).

# CX-6 Dx: EN→IB + рут

Установлено офлайн (2026-09-26, `mlxfwutil diff` по образам `refs/fw/cx-5-6`):
MCX623435AN-CDA (EN 100G, PSID `MT_0000000694`) ↔ MCX683105AN-HDA («CX-6
DE» IB HDR, PSID `MT_0000000903`), оба rel-22_50_1002, device_id 4125 —
**весь код и весь DTOC побайтово идентичны** (вкл. оба PHY-микрокода и
PROG_HW_FW1/2); дельта = ~117 Б конфигов (0x08: 69 Б, 0x09: 35 Б, 0x11: 4 Б,
0x12: 9 Б) + идентичность (0x10/0xE0) + digest (0xA0). PRS-имя HDA —
`cx6-dx_CX683105A_IB_HDR_1p.prs`: сборка вендора сама считает DE вариантом
cx6-dx. Третий референс той же платы — VDA (PSID `MT_0000000457`, 200GbE EN,
secure). Задел от проекта cx6dx-bazzite: VPI-байт CX-6 Dx = `0x11+0x2df`
(не 0x2b7, как у CX-5; значения сверены именно с образом 903); `guides` на
Dx работает (device-data вне RSA-подписи — S2); блокер был один — FB-карта
GA SECURED (0x11-патч → no-boot, C3).

**C3-статус (2026-10-31, цикл cx6dx-introspection — отчёт
`docs/superpowers/reports/2026-10-31-cx6dx-introspection.md`, docs/250-re/110-signing/055-cx6dx-signing.md):
блокер дефинитивен.** VPI-патч на GA SECURED — no-boot доказан live при
всех классах подписи: D1 (стейл-вендор-RSA + валидный fresh 0xA0), a2d
(наш 0xA4 slot0 + вендорский фоллбек slots 1/2 + наш 0xA1 + наши
0xA3/0xA7 + валидный 0xA0) и a3c (a2d + наша X.509-цепочка, certs
доставлены бит-экзакт) — все доставлены FNP байтово и не грузятся ⇒
boot root-of-trust ВНЕ flash (HB-b, confound-free; OTP/fuse/mask ROM —
точный механизм не установлен; скоуп — этот GA SECURED кремний).
Кросс-базовый кложур: пара fbss/fbctl на FB-базе (FW 22.32.1224;
единственная дельта = класс ключей) — NO-BOOT/BOOT ⇒ анкор пинит
вендорские ключи и на FB-пути. Финальное состояние: карта оставлена на
fbctl (FB-vendor контроль, порт Active 40G); владелец перепрошивает на
свежий FW 2026-11-01. EN→IB на secure-карте перепрошивкой закрыт;
трек остаётся за non-secure Dx-картой (MCX623105AN-CDAT). IB-биты-задел
(journal task-01 Step 5): минимальный кандидат EN→IB = ITOC 0x11+0x2df
0x0a→0x05 (+ возможно 0x12 speed-байты, 9 Б); NV_DATA0/2 идентичны EN↔IB
(NV-путь не нужен); HW_*-секции 0x08/0x09 — board-уровень чужой платы
(CX683105A IB-плата ≠ AN-CDA EN-плата: GPIO/serdes/i2c/core_pll), не
копировать.

Железо (обе на руках → трек ведём независимо от CX-5):

- CX-6 Dx **FB (OCP, secure)** — root-bazzite 04:00.0, docs/050-hardware/100-inventory (блокер
  «0x11-патч на SB» — материал для secure-ветки)
- **MCX623105AN-CDAT куплена (Ali, 2026-09-26)** — стикер: Model CX623105A,
  Rev AC (= PCB-ревизия, по прецедентам docs/050-hardware/100-inventory: B4/86/B7/A9 — не суффикс
  SKU), S/N `MT23263002YJ`, MAC — со стикера (замер при приезде карты,
  до измерения не фиксируется), 2023-06-25. PCIe HHHL,
  1×QSFP56 100GbE, суффикс **AN = No Crypto, без Secure Boot** → SB-блокер
  квеста снят. OPN «MCX630105AN-CDAT» в листинге — опечатка продавца
  (в каталоге NVIDIA не существует, user manual: только 623105AN/AE/AC).

Опция (отложена, решение по результатам): **CX-6 Lx** — рут по тому же
пути; цена AN+AS-карт Lx ≈ одной Dx AN; покупка гейтится на полном руте
CX-5 (окупаемость инвестиций). Dx-трек от CX-5 не зависит: там модель
защиты слабее и успех автоматически не переносится, а пара
secure/non-secure Dx-образцов уже на руках.

Опция (дальняя, после Dx-трека): **BlueField-2** — вынесено в TODO.md,
раздел «BlueField-карты: исследования» (2026-10-03): NIC-квест EN→IB +
DDR3/ES-ARM + новый PCIe host/consumer; покупка гейтится на результатах
Dx-трека.
