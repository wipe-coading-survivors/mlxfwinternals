# irisc/ — тулинг RE iRISC

Две части каталога:

1. **irisc-asm** — канонический ассемблер/энкодер iRISC-слов + профили +
   clcrc-API + кросс-декодер-гейт (`docs/010-roadmap/100-irisc.md`
   Фаза III, 2026-10-15).
   Спека `docs/superpowers/specs/2026-10-15-irisc-asm-design.md`, план
   `docs/superpowers/plans/2026-10-15-irisc-asm.md`, ветка `irisc-asm`
   (`6bd820d..251990e`). Скилл для агентов — `skills/irisc-asm/SKILL.md`
   (канон в репо; там же блок конвенций слов: BE, dc↔rt, CR-маппинг).
2. Research-скрипты RE-сессий (Фаза I, таблица ниже) — скопированы из
   `/tmp/opencode/irisc/` (2026-09-23) для сохранности; пути к бинарям и
   журналам захардкожены под конкретные сессии — при использовании править
   под себя. Live-HW пробы (`pc3_probe*.py`, DEV 81:00.0) — только через
   субагента (AGENTS.md `live-hw-subagent`, docs/850-howto/100-cross-flash-ops).

## irisc-asm

### Import-рецепт

Работать из корня репо mlxini; если CWD другой — вставить корень репо в
`sys.path` (иначе `mlxfwutil` не импортируется):

```python
import sys; sys.path.insert(0, "/path/to/mlxini")
from scripts.irisc import (assemble, disasm, encode_form,
                           clcrc_unwrap, clcrc_wrap, AsmError)
```

- `assemble(text, base=0, profile=None, strict=True, allow_assumed=False)
  -> bytes` — BE-слова (`>I`), эмит с **decode-verify** каждого слова
  (слово немедленно декодируется `irisc_dis` и сверяется с запрошенной
  формой по полям; расхождение — `AsmError`, а не молчаливый мусор);
- `disasm(word, off)` — re-export канона `scripts/irisc/irisc_dis.py`;
- `encode_form(mnem, pos=0, **fields) -> int` — одно слово (в т.ч.
  `op0xNN`, `alu.0xNN`, `b.t.0xNN`);
- `clcrc_unwrap/clcrc_wrap` — см. clcrc-API ниже;
- `scripts/irisc/enc.py` — старый S2/S3-API (`set0/st_d/jump/...`),
  делегирует ядру (S2-скрипты не ломаются); для нового кода — ядро.

### Синтаксис: канон-слой / сахар / синдикат-диалект

Три уровня, все живут в одном парсере (`irisc_asm.py`):

1. **Канон-слой (dis-canonical)** — ровно то, что печатает
   `irisc_dis.dis()`: `addi/set0..set3/st.d/ld.w/jump/call/b.t.0x0a/...`
   + `and.hi rd,rs,imm16` (op 0x0d) — canon-sync 2026-10-25 (fuzz-4
   2-confirmed, канон сласпек = источник истины: порядок
   операндов/мнемоника — по конструкторам `iRISC.slaspec`, golden-пары
   из фактического Ghidra-вывода) + `andmsk.hi rd,rs,imm16` (op 0x0c
   imm, hi-and маска `(imm16<<16)|0xffff`, семантика смёржена 06be769;
   унаследованное имя immediate-формы `or` удалено — canon-sync
   2026-11-01; register-`or` (`op 0x3f funct=8`) — настоящее OR,
   сохранён) + generic-формы `op0xNN rd,rs,rt imm=0x…` (любой
   unknown-op), `alu.0xNN`, `dword 0x…` (raw-литерал). Мнемоника
   `bclr.1 rd,rs` (op 0x34, imm11=0x022, canon-sync 2026-10-25) снята —
   canon-sync 2026-11-02: слот смёржен как `:dep.c`-литерал
   (`RDlo = (RSlo & ~0x6) | 0`, P-formula вердикт isa-max-B, live X/Y
   батарея), слово покрывается lossless-формой `op0x34` (rt-поле
   читается). На
   lossless-подмножестве форм текст↔слова бит-экзакт (golden-тесты
   `tests/test_irisc_asm.py`); lossy-классы — см. реестр ниже
   (гарантирован fixpoint).
2. **Сахар** — удобные многословные/алиасные формы, раскрываются в
   канон до эмита: `set32/set64` (→ set2+set3 / set0..set3),
   `cmp36_eq32/cmp38_eq32` (→ op0x36/0x38 imm=2), `alur.0xb` (→ ands#alu),
   `b.set/b.clr` (→ b.bset/b.bclr), трёхаргументные `b.t/b.f cc,rs,tgt`,
   reg-reg `and/ands/or/xor` (→ `…#alu`; immediate-форма op 0x0c —
   только каноническая `andmsk.hi`, старое написание `or rd,rs,imm`
   удалено), метки `lbl name` + символные
   таргеты branch/jump/call.
3. **Синдикат-диалект** — совместимость с .asm-корпусом синдиката
   (`refs/src/irisc-research-syndicate_mlx5cmd/shellcodes/test_*.asm`):
   q-form mem-операции по арности (см. таблицу ниже), `unk.r/unk.i`
   (raw-формы, мост к unknown-op), `alu.r`; jinja2-шаблонизация исходника
   (`assemble_templated`; jinja2 — ленивый import, ядро работает без него).

CLI (`python3 -m scripts.irisc.irisc_asm`): главный assemble-интерфейс
**вендор-совместимый** — `--int-arg key val`, `--str-arg key val`,
`--base 0x…`, позиционные `source out`; проверочные субкоманды поверх:
`roundtrip` (слово→dis→asm→…; метки exact/fixpoint/DRIFT, exit 1 при
ERROR/DRIFT), `disasm`, `profile` (список форм со статусами).

### Профили (`profiles.py` + `profiles/{cx5,cx4lx}.json`)

- Нейминг по поколениям: **cx5** (verified_on 16.35.4030 CDA + 8008
  оговорки; 51 форма) и **cx4lx** (14.32.1900-GCA; 48 форм); `load_base`
  (MAIN_CODE → 0x800000), якоря, unknown-census (Фаза I0/fuzz-3).
  Мнемоника `and.hi` — `static` в обоих профилях (canon-sync
  2026-10-25); `bclr.1` снята из форм и профилей (canon-sync
  2026-11-02, слот 0x022 → `:dep.c`-литерал slaspec); `andmsk.hi`
  (op 0x0c imm) — `live` на cx5, `static` на
  cx4lx/cx6dx (canon-sync 2026-11-01); census-записи 0x0d/0x34/0x0c
  сохранены как исторические факты Фазы I0 и от правок dis/asm не
  зависят.
- Статусы форм: `live` (прожигами) / `static` (golden/статика) /
  `assumed` / `unknown`. **Strict-гейт по умолчанию**: форма вне
  live/static при `assemble(..., profile=…, strict=True)` — `AsmError`;
  разблокировка — `allow_assumed=True`.
- `annotate(text, profile)` — аннотирует дизасм-текст census-заметками
  unknown-op (`; [cx5] predicate-compare …`).
- Известное ограничение: профиль **cx6 отложен** (владелец, 2026-10-15);
  добавим при появлении CX-6-потребителя.

### clcrc-API (de-clcrc/clcrc-фрейминг, канон в `mlxfwutil`)

Секции clcrc=1 фреймированы 68B-линиями: 64B код + 2B ноль-пад + 2B LE
u16 clcrc (CRC-область 66B). Канонические функции в `mlxfwutil.py` (re-export
в `scripts.irisc`): `clcrc_calc`, `clcrc_lines_errors`, `clcrc_unwrap(raw)
-> (payload, tail)`, `clcrc_wrap(payload, tail=b"") -> raw`. Round-trip-гейт
`clcrc_wrap(clcrc_unwrap(raw)) == raw` на реальных MAIN_CODE 4030 и
1900-GCA (тесты `tests/test_clcrc_api.py`). Развёртывание фрейминга руками
по скриптам больше не пишется.

**Не мигрированы на канон-API (отложено, Task 3 Step 5):** probes-копии
clcrc-фрейминга — `scripts/probes/*` (вкл. `wall8k_scan.py`),
`scripts/irisc/build_fuzz_aca.py`, `scripts/s1/*`.

### Кросс-декодер-гейт (`crosscheck.py`, Ghidra × irisc_dis)

```sh
make irisc-crosscheck IMG=<fw-image>            # IRISC_CROSSCHECK_SLASPEC={repo,upstream,both} (default both)
                                                # OUT=<report.json> (default build/irisc-crosscheck-<img>.json)
```

Линейно по всей MAIN_CODE (code+data) сравнивает headless-Ghidra
(контейнер `ghidra-irisc`) с `irisc_dis`; каждый дифф классифицируется в
таксономии {documented | outside_slaspec | data | decoder_bug}.
**Гейт = `report_pass`: unclassified == 0 и decoder_bug == 0** (exit 1
иначе). Прогон
2026-10-15: 4030 CDA (941936 слов) и 1900-GCA (815872 слов) — обе
конфигурации slaspec (repo + upstream пин 4c488a4), decoder_bug=0,
unclassified=0, PASS (отчёты в `build/`, журналы task-04).
Прогон canon-sync 2026-10-25 (4030 CDA, both, канон печётся в образ):
repo-нога outside_slaspec 15595 → 11960 (−3634 and.hi − 1 bclr.1 →
class none при текстуальном совпадении рендеров), upstream-нога без
изменений (15595), decoder_bug=0, unclassified=0, PASS.
Прогон canon-sync 2026-11-01 (переименование 0x0c imm → andmsk.hi):
repo-нога без изменений (обе ноги рендерят andmsk.hi → none),
upstream-нога: 0x0c-слова ours=`andmsk.hi` vs upstream=`or` →
documented (точечное правило `_documented`), decoder_bug=0,
unclassified=0, PASS (счётчики — журнал isa-max-a task-09).

### Таблица соответствия мнемоник (st.d vs st.q-класс)

Одна мнемоника — два разных класса формы; разруливаются **арностью**:

| Синтаксис | Арность | Класс | Слово |
|---|---|---|---|
| `st.d rt,rs,off` (наш канон) | 3 | **rd-форма**: rs-база + знаковый off14 (×4) | op 0x1b, биты [1:0]=2 |
| `st.d rt,rs,rd,off11` (синдикат) | 4 | **q-form**: rt + off11 + twobits (funct) | op 0x1b, funct=off11\|2 |
| `ld.d rd,rs,off` (наш канон) | 3 | rd-форма | op 0x19, биты [1:0]=2 |
| `ld.d rd,rs,rt,off11` (синдикат) | 4 | q-form | op 0x19, funct=off11\|2 |
| `st.q rt,rs,rd,off11,twobits` (синдикат) | 5 | q-form | op 0x1e, funct=off11\|twobits |

Аналогично наши канонические `ld.q.17/st.q.1e/st.d!` (imm-офсет) vs
синдикатные q-form через `unk.r` (funct = off11|twobits). Наш `st.d`
(rd-форма) — live-proven (docs/250-re/120-irisc/025-boot-injection.md v3, S2 v5l); q-form-класс — рендер
Ghidra/slaspec-имена, эмит через raw-форму с decode-verify.

### Мнемоники op 0x0c: `andmsk.hi` (imm) vs `or` (register)

Один опкод-класс — две разные формы с разными именами (canon-sync
2026-11-01): immediate-форма op 0x0c — **`andmsk.hi rd,rs,imm16`**
(hi-and маска: rd_lo = rs_lo & ((imm16<<16)|0xffff); imm16 беззнаковый);
register-форма op 0x3f funct=8 — **`or rd,rs,rt`** (`or#alu`, настоящее
OR, live-proven). Профили: `andmsk.hi` — live на cx5 (fuzz5-батарея
V-C2R-0Cx01ff), static на cx4lx/cx6dx; ключ `or` в профилях остаётся за
register-формой (strict-гейт проверяет исходную мнемонику до
ALU-alias). Crosscheck: upstream-нога рендерит унаследованное `or` —
пара «наш `andmsk.hi` / upstream `or`» при тех же операндах
классифицируется documented (`_documented`).

### Полный lossy-реестр рендеров (dis-текст не восстанавливает слово)

Рендер `irisc_dis` не покрывает все биты слова; re-асемблирование
dis-текста канонизирует (теряемые биты → 0), гарантируется **fixpoint**
(слово → dis → asm стабильно; базовые классы — тест
`test_lossy_fixpoint_per_class` в `tests/test_irisc_asm.py`, полные
множества теряемых бит — эмпирические roundtrip-пробы):

| Рендер | Теряемые биты | Канонизация |
|---|---|---|
| `ld.q.17` / `st.q.1e` (q-form) | биты 0 и 2: бит 0 рендером не читается (дис различает d/q только битом 1), бит 2 — офсет печатается `& ~7` | бит 0 → 0; align-down 8 (asm сам делает `off &= ~7`) |
| `ld.d.17` / `st.d.1e` | бит 0 (рендером не читается; см. q-form) | → 0 |
| `csr.w` (cf≠0x1b) | биты 20..16 (поле cf) | → 0 |
| `csr.r` | биты 24..21 (поле rs) + биты 15..11 (старшие биты imm16-поля) — печатается только rd + imm11 | → 0 |
| `st.i` (cf=0x1b) | биты 15..11 (поле rt) | → 0 |
| `ld.i` | биты 24..21 (поле rs) | → 0 |
| `alu.0xNN` | биты 10..9 (между rt и funct) | → 0 |
| `mask32` | биты 15..11 (мусор; m = биты 10..5 и n = биты 4..0 рендерятся полностью) | → 0 |
| `addi` (ops 0x00/0x01) | бит 26 — op-lsb: оба опкода рендерятся одинаково | op → 0x00 |
| `addi.hi` (ops 0x02/0x03) | бит 26 — op-lsb: оба опкода рендерятся одинаково | op → 0x02 |
| `shr` (funct 0x8a) | funct: 0x8a — алиас 0x83, рендером неразличимы | funct → 0x83 |

Прочие рендеры канон-слоя — lossless (бит-экзакт), включая mem-опы
0x19/0x1b/0x1c — оба младших бита слова потребляются рендером
(бит 0: w-форма, бит 1: d vs q), `and.hi` и `andmsk.hi` (imm16
печатается беззнаковым — как unsigned-токен сласпека; на корпусе 4030
все 3634 слова and.hi roundtrip бит-экзакт). Проверка на arbitrary
бинаре: `python3 -m scripts.irisc.irisc_asm roundtrip <bin>` (метки
`exact` / `fixpoint` / `DRIFT`).

## Research-скрипты (Фаза I)

| Скрипт | Назначение |
|---|---|
| `irisc_dis.py` | Word-декодер iRISC (исправленный: таргеты веток `PC+o*4`, составные знаковые офсеты ld/st — golden-тесты `tests/test_irisc_dis.py`) |
| `enc.py` | Энкодер инструкций (слова) для шеллкодов (делегирует `irisc_asm.py`) |
| `build_4030_patch.py` | Сборка патченного 4030 CDA: boot-injection + шеллкод (docs/250-re/120-irisc/025-boot-injection.md) |
| `analyze2.py` | Разбор Ghidra DumpRange-логов |
| `find_magic.py` / `find_set2.py` / `set01_scan.py` | Поиск магов / set2- / set0/set1-констант в de-clcrc бинаре |
| `free_scan.py` | Скан свободных карманов под шеллкод |
| `mmio_scan.py` | Скан MMIO-паттернов |
| `trace_boot.py` | Декод-трассировка boot-цепочки (ROM→MAIN, docs/250-re/120-irisc/025-boot-injection.md) |
| `pc3_scan.py` | Offline-скан CR data-channel (PC3) |
| `pc3_probe.py` / `pc3_probe_smoke.py` / `pc3_probe_full.py` | Live-пробы VSEC/CR через sysfs config (инцидент PC3 — без плотных циклов) |
| `recount_codehist.py` | Чистый пересчёт неизвестных op (code-vs-data классификатор; журнал `2026-09-23-irisc-unknown-ops-recount.md`) |
| `snips.py` | Контекст-сниппеты топ неизвестных op (исправленный форматтер) |
| `s1_callers.py` … `s1_upstream.py` (`s1_*.py`) | Offline-сканы для S1-локатора: callers, jalr-xref, LOC-кодировка, populate, upstream, opc_extract, datascan, containing, loc_audit |
| `t1_scan.py` | T1-скан (wrapper-кандидаты) |
| `iRISC.slaspec.patch` | **Канон slaspec (tracked)**: дельта upstream@`4c488a4` → наш канон; заголовок — пин апстрима, `upstream-sha256` (pristine), `result-sha256` (канон). Мёрж-волна: `slaspec_patch.py regen --canon <полный файл>` → коммит патча |
| `slaspec_patch.py` | Патч-как-канон: `gen` — материализует ОБА untracked-файла из патча (fetch/verify → apply → verify; источник — env `SLASPEC_UPSTREAM`/`--upstream` URL\|путь, кэш `build/slaspec-cache/`; офлайн без кэша — rc 2 warn, integrity-отказ — rc 1), `regen` — перегенерация патча из (upstream, канон), идемпотентен |
| `iRISC.slaspec` | Sleigh-спека iRISC — **источник истины мнемоник/рендеров** (untracked-генерация из патча, `make slaspec-gen`): база синдиката (пин `4c488a4`) + канон-расширения (`and.hi`, 061d7e0; переименование 0x0c imm → `andmsk.hi`, canon-sync 2026-11-01; мёрж-волны `:dep.c`-литералов 0x34 — A 26 + B 46 вкл. слот 0x022 (снятие `bclr.1`), canon-sync 2026-11-02); контейнер (`ghidra-irisc.containerfile`, образ `mlxini-ghidra-irisc`) — в компаньоне ghidra-container; содержит generic `unk.^op` catch-all — decode-gaps от неизвестных op невозможны |
| `iRISC.upstream.slaspec` | Апстрим-копия спеки для independence-прогона кросс-гейта (untracked-генерация; **pristine fetched-байты** upstream@пин, без аннотационного заголовка, sha256-пин в crosscheck.py) |
| `imgate.py` / `imgate2.py` | Image-gate бёрна: бит-в-бит сверка flash-дампа vs образ ПО зазором (gap `0x557660..0xF90000`; v2 = по регионам body/gap/tail, MTCF/DTOC). Pre/post-burn гейт (журналы s3, task-03) |
| `diag_tail.py` | Разбор 16 MiB-дампа vs образ по регионам (3-way: дамп/v5q/v5o; s3 task-08/11) |
| `t17r-run.sh` | Раннер R12-проб S2 task-17 (nohup + поллинг ≤30 с, HANG-кап; журнал `2026-09-24-irisc-ondemand-s2-task-17.md`) |
| `trace-sites.tsv` | **Данные RE (не скрипт)**: полная таблица iTrace trace-сайтов v5q (1861: `site family target class class_name level str_rt string`; task-02 mstfwtrace-followup, журнал `2026-10-08-…-task-02.md`). Генерирующий скан в репо не сохранён — файл несъёмный |

Бинари/выводы этих скриптов — в `/tmp/opencode/irisc/` (в репо не кладутся).
