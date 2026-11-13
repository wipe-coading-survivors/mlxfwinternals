# 120. Field-merge: методология сборки кастомной прошивки из частей

> Статус: методология (глава 3, 2026-09-12). Кейсы E5/4706 — проверены
> (docs/750-exp/110-dell-base-rework, docs/850-howto/140-fw-upgrade). Кейс E-code — глава 5 спеки (закрыт в T5.6, 2026-09-13).
> Факты — в спеке `docs/superpowers/specs/2026-09-10-eda-ib-node-design.md`
> (§3.3 R1–R3, §1.2); модель смешиваемости и гейты — docs/550-poc/100-mlxfwutil/020-patch-matrix.md.

## 1. Когда применять

- Цель = «новый код + OEM-дельта» (R2) либо «смена идентичности/конфига в
  базе» (R1): дельта — поля/секции, а не целый код.
- Код (0x02–0x07, 0x0a–0x0c, 0x20) **не пересаживается** в чужую базу
  (digest — docs/550-poc/100-mlxfwutil/020-patch-matrix.md): «новый код» = весь новый base-образ, к нему
  шьётся OEM-дельта.

## 2. Шаги

1. **Дельта**: `python3 mlxfwutil.py diff <base> <src> --max-ranges 64` —
   per-section diff; полевой разбор (смещение/длина/значение — по карте
   частей docs/250-re/100-formats/020-fs3-sections.md и docs/550-poc/100-mlxfwutil/020-patch-matrix.md).
2. **Include/exclude-классификация** с обязательными exclusion-листами:
   - **всегда исключать**: подписи 0xA0–0xA5 (только от базы; non-SB — не
     переподписываем), кодовые секции 0x02–0x07/0x0a–0x0c/0x20
     (digest-модель);
   - **структурные**: 8MiB-half (секция не должна пересекать границу
     0x800000); размерные расхождения (диапазон должен помещаться в
     секции **и** base, **и** src — guard'ы `merge`).
3. **Completeness-control**: КАЖДОЕ поле/секция дельты — либо в include-
   сете, либо в exclusion c причиной. «Потерявшихся» полей нет. Контроль —
   построчное сопоставление вывода diff ↔ (include + exclusion).
4. **Финальный --spec-лист как артефакт**: список
   `0xNN+0xOFF+LEN` (+ `psid`/`repack --swap` для целых секций)
   фиксируется в доке и в команде сборки — воспроизводимость: та же
   команда → тот же образ (md5).
5. **Эталон-сверка**: значения PRS/ini и полей эталона целевого железа
   (например 1012-EDA — эталон 100G QSFP28 VPI) сверяются: порт-конфиг —
   как требует целевое железо, OEM-идентичность (PSID/sub/MFG_INFO/
   description) — как у OEM-образа.
6. **Сборка и гейт**: `python3 mlxfwutil.py psid` / `patch` / `merge` /
   `repack --swap` → **офлайн-гейт** (docs/550-poc/100-mlxfwutil/020-patch-matrix.md) → только затем burn
   (non-SB: `-apc`). Post-burn sanity — после каждого burn.

## 3. Кейсы

### 3.1 E5 (docs/750-exp/110-dell-base-rework) — Dell-идентичность на ADA-карте (проверено)

База 1012-ADA + PSID `MT_0000000009` + sub + .ini 0x30 (из эталона
1012-EDA) + поля 0x11/0x12 → бут с первой попытки, IB-класс [0207].
Паттерн R1: конфиг-дельта в вендорной базе, legacy-burn.

### 3.2 4706 (docs/850-howto/140-fw-upgrade) — код + config-graft (CX-4/FS3, проверено)

Новый код + пересаженный конфиг: plain burn FAILS (digest) →
`--no_fw_ctrl` (legacy) PASS. Подтверждает flash-путевую модель
docs/550-poc/100-mlxfwutil/020-patch-matrix.md: modified-образы — только legacy/FNP.

**Версионный симптом + ловушка «версионные на вид» поля (кейс —
docs/850-howto/140-fw-upgrade-fw-upgrade.md §11).** При graft config (OEM-дельта) на новый код
**допереносить версионные stamps** — иначе рассинхрон: running-FW
отчитывается версией из config (iseg/health), а flash/`mstflint q`/`devlink`
— версией кода. При классификации include/exclude (§2.2) каждый
«version»-кандидат **проверить, что он версия, а не port/SKU/идентичность** —
в том кейсе два таких поля (`0x11:0x35` SKU, `0x11:0x1a..1b` порт) при
переносе из dual-базы перевернули single-карту в dual. Правило: в «version» —
только stamps, подтверждённые сверкой значения↔версия на паре single/dual
того же релиза; port/SKU/ident — от целевого железа (§2.5).

### 3.3 E-code (глава 5, 2026-09-12/13) — 8008-ECA + Gen4 + порт-конфиг

Закрыто в T5.6 (2026-09-13). Фактическая база — **8008-ECA** (эррата к
изначальному 8008-CDAN — таблица в docs/750-exp/120-eda-ib-node §5.1). Финальный field-map
(4 Gen4-поля: `0x08+0x23`, `0x09+0x86c..f`, `0x11+0x47`, `0x11+0x93`;
порт-конфиг — ad-hoc t53h/t53i (2026-09-13): `0x11+0x2b7=0b` (VPI def-ETH)
в образе, **без NV-override** — `0x03` оказался мисдекодом, docs/750-exp/120-eda-ib-node §5.5)
— docs/750-exp/120-eda-ib-node §5.3. Md5: t52_g4 `cee795cb…`, t53_final `5e156943…`,
t53g (guides) `1fd5c1bb…`; финальное состояние — t53i (raw `970636c6…`,
valid B). Репродукция: `TestCh5EcodeMergeRepro` (tests/test_mlxfwutil.py) —
пересборка из 8008-ECA → побайтовый md5 + no-op merge.

## 4. Шаблон: 6120 ↔ 4030 (secure-фаза, карта 41:00.x)

Известные факты (docs/750-exp/100-dell-base-vpi-build, docs/750-exp/110-dell-base-rework):

- 6120 (rel-16_27_6120, Dell `09FTMY`) vs 4030 (rel-16_35_4030): **код
  различается** ⇒ mixed-CODE — только FNP-путь (нет running-FW-пути);
- S1 (код 4030 + конфиг 6120): **no-boot** (docs/750-exp/100-dell-base-vpi-build §2.2–2.4; dense-
  укладка — карты нет в PCI, layout-preserving — остаётся в FNP);
- MCC (plain) **отклоняет** modified-образы (digest);
- подпись **не переподписывается** (нет non-SB-ключа) ⇒ merge-образ
  собирается как **unsigned-кандидат**, вердикт — FNP-burn.

Что собрать офлайн (в нашей фазе, без 41:00.x):

- field-map 6120↔4030 по docs/750-exp/100-dell-base-vpi-build §1.3/§1.4: размерные расхождения
  (0x12: 0xc00/0xb00; 0x09: 0x1580/0x980) ⇒ НЕ простой range-merge —
  `repack --swap` для секций с разным size + field-merge в пределах
  общего size;
- exclusion-листы (код + подписи) и completeness-список по §2.2–2.3.

Что проверять на 41:00.x (secure-фаза, НЕ в этой фазе — §4 спеки:
никаких операций): FNP-burn кандидата, post-burn sanity, идентичность/
порты.
