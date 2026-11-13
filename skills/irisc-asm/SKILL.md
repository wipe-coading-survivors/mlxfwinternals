---
name: irisc-asm
description: Use when working with iRISC words in Mellanox ConnectX firmware — assembling shellcode/stub words or fuzz vectors, disassembling MAIN_CODE dumps, dc↔rt address math, host-CR↔RAM↔regspace mapping, clcrc 68B-line (de)framing, per-generation profiles (cx5, cx4lx), decode-verify/strict gates.
---

# irisc-asm (ассемблер/энкодер iRISC, репо mlxini)

Канон — этот файл в репо (`skills/irisc-asm/SKILL.md`, версионируется с
кодом). В `~/.config/opencode/skills/irisc-asm/` — реальный каталог +
file-симлинк `SKILL.md` → репо-файл; сломанный/отсутствующий линк виден
сразу, восстановление — из git. `.py` в каталог скилла НЕ линкуются:
импорт — только из репо (рецепт ниже).

Симлинк (из корня checkout'а репо):

```sh
mkdir -p ~/.config/opencode/skills/irisc-asm
ln -sf "$(git rev-parse --show-toplevel)/skills/irisc-asm/SKILL.md" \
  ~/.config/opencode/skills/irisc-asm/SKILL.md
```

Fallback, если discovery симлинк не берёт (спека §5) — копия + md5-контроль
(после обновления репо-файла перезапустить и сверить md5):

```sh
REPO="$(git rev-parse --show-toplevel)"
mkdir -p ~/.config/opencode/skills/irisc-asm
cp "$REPO/skills/irisc-asm/SKILL.md" ~/.config/opencode/skills/irisc-asm/SKILL.md
md5sum "$REPO/skills/irisc-asm/SKILL.md" ~/.config/opencode/skills/irisc-asm/SKILL.md
```

## Import-рецепт (обязательный)

Работать из корня репо mlxini; если CWD другой — вставить корень репо в
`sys.path`:

```python
import sys; sys.path.insert(0, "/path/to/mlxini")
from scripts.irisc import (assemble, disasm, encode_form,
                           clcrc_unwrap, clcrc_wrap, AsmError)
from scripts.irisc.profiles import load_profile, annotate
```

CLI (из корня репо):

```sh
python3 -m scripts.irisc.irisc_asm --int-arg r5 5 --base 0x0 <src> <out>  # главный, вендор-совместимый
python3 -m scripts.irisc.irisc_asm disasm <bin> --base 0x0                # слова → текст
python3 -m scripts.irisc.irisc_asm roundtrip <bin> --base 0x0             # exact/fixpoint/DRIFT
python3 -m scripts.irisc.irisc_asm profile                                 # формы+статусы
```

## Конвенции слов (live-proven; не выводить самому)

- **Big-endian.** Все слова iRISC и FW-кода — BE: файл, память, fetch.
  Исключение — секция ROM (0x18 ROM_CODE): там x86/arm64-код (FlexBoot
  PCI option ROM + EFI-суб-образы, docs/250-re/100-formats/020-fs3-sections.md)
  — он little-endian; BE-конвенция
  — про iRISC-секции ITOC (0x02..0x15).
- **dc ↔ rt/live-PC:** load base MAIN_CODE — по поколению, из профиля
  (`load_base`) или ITOC param0 секции 0x03: cx5/cx4lx **0x800000**
  (rt = dc + 0x800000; пример: dc 0x38d730 ↔ rt 0xb8d730);
  **cx6dx 0x21000000** (22.50.1002, верифицировано консенсусом пар
  addi/addi.hi 98.8%, журнал cx6dx-securefw task-02).
- **Host-CR ↔ RAM ↔ regspace:** offset X ↔ iRISC RAM[X] ↔ regspace
  0x40000+X (mapped-слоты; unmapped-дефолт = off/4).
- **68B-фрейминг clcrc=1-секций:** строка = 64B код + 2B ноль-пад +
  2B LE u16 clcrc (CRC-область 66B); полезные байты строки = 64,
  не 66/62. Развёртывание руками не писать — есть
  `clcrc_unwrap(raw) -> payload` / `clcrc_wrap(payload) -> raw`.

## Профили

`scripts/irisc/profiles/{cx5,cx4lx,cx6dx}.json` — нейминг по поколениям,
внутри `verified_on` (cx5 → 16.35.4030 CDA; cx4lx → 14.32.1900-GCA),
статусы форм (live/static), unknown-op census (`annotate` добавляет
census-заметки в дизасм-текст).

```python
assemble(text, base=0x38d730, profile="cx5")   # strict по умолчанию
assemble(text, profile=load_profile("cx4lx"), allow_assumed=True)
```

Live-proven формы (по live-прецедентам; канон статусов — JSON-профили
и `profile`-подкоманда, не этот список): `set0..set3`, `addi`,
`st.d` (абс. и база+офсет), `st.d!` (push), `ld.w`/`st.w`, `ld.d`,
`jump`, `call`, `cmp38_eq32` (funct5=2), `b.t`/`b.f` (cc 0x0a),
`ret.r` (no-link), `or`, `shl64.i`, `csr.w` (cx5). `csr.r` — **static**
(оба профиля), не live. Остальные формы профилей — static
(декодер-proven); raw `op0xNN`/`unk.*` strict-гейтом
не блокируются (это осознанная эмуляция unknown-op).

Canon-sync 2026-10-25 (канон мнемоник — `iRISC.slaspec`, см. Указатели):
`and.hi rd,rs,imm16` (op 0x0d, imm16 беззнаковый) — static в обоих
профилях; `bclr.1 rd,rs` (op 0x34, lo11=0x022) — снята canon-sync
2026-11-02: слот смёржен как `:dep.c`-литерал (`RDlo = (RSlo & ~0x6)
| 0` — P-formula isa-max-B, live X/Y батарея), asm-форма и профиль-ключи
удалены, слово пишется lossless-формой `op0x34 rd,rs,rt imm=0x…`.

Canon-sync 2026-11-01: `andmsk.hi rd,rs,imm16` (op 0x0c imm, imm16
беззнаковый; hi-and маска — rd_lo = rs_lo & ((imm16<<16)|0xffff),
семантика смёржена 06be769) — унаследованное имя immediate-формы `or`
УДАЛЕНО. Register-форма `or rd,rs,rt` (op 0x3f funct=8, `or#alu`) —
настоящее OR, НЕ переименована. Статусы: `andmsk.hi` live на cx5
(fuzz5-батарея V-C2R-0Cx01ff), static на cx4lx/cx6dx; ключ `or`
в профилях — за register-формой. Crosscheck: пара «наш `andmsk.hi` /
upstream `or`» при тех же операндах — documented-правило.

## Гейты (нарушение = кирпич-риск на карте)

- **decode-verify:** каждое эмитнутое слово немедленно декодируется
  каноном (`irisc_dis`) и сверяется по полям; несовпадение — `AsmError`.
  Успешный `assemble` = все слова верифицированы, отдельного прогона
  не нужно.
- **strict-профиль:** формы вне live/static блокируются; assumed —
  только с явным `allow_assumed=True`. Для бёрна всегда передавай
  профиль целевого билда.
- **cmp38 funct5=2 (eq32):** писать `cmp38_eq32 rs,rt`. funct5=0 →
  trap CPU (live-факт S2 R9).
- **set3 rs=rd = OR-семантика (ловушка):** rs=zero — чистая запись
  младших 16 бит; rs=rd — OR со старым значением (старшая половина
  обычно уже в rd после set2). Кодирование бито-экзактно roundtrip-ится
  — decode-verify эту ошибку НЕ ловит, следить за rs вручную.

## Рецепты (golden-прецеденты)

- **v3-детур (cx5/4030):** docs/250-re/120-irisc/025-boot-injection.md — `call` в шеллкод из boot-точки,
  маркер CR 0x23f0 = 0xbadc0001; шеллкод 6 слов @ base 0x38d730, resume
  `jump 0x1e10c`. Тест-прецедент: `tests/test_irisc_asm.py`.
- **S2-префикс (cx5/4030):** `scripts/s2/build_s2.py`, слова w0–w13
  (v5l: csr.r-фильтр + echo-канал); сахар-источник —
  `test_stub_recipe_s2_v5l_prefix_from_sugar`.
- **H0-хук / T2-стаб (cx4lx/1900-GCA):**
  `scripts/probes/cx4lx-detour/build_cable_t2.py` (`emit_stub("H-AN")`).
- **unk-вектор для fuzz:** неизвестный op — `op0xNN` (parse-back
  дизасма, lossless) или `unk.r`/`unk.i` (raw-биты). Например
  op0x36 funct5=4: `op0x36 zero,r5,zero imm=0x0004` (lo11 =
  imm6|funct5 = 0x004; бито-экзакт live-слову билдера
  `enc.cmp36(0,5,0,0x004)`; семантика 0x36 predicate-compare, карта
  f5 открыта — census в профиле).

## Известные ограничения

- **Профиль cx6dx добавлен** (2026-10-30, цикл cx6dx-securefw task-02):
  offline static decode 22.50.1002 refs-VDA, все формы `static`
  (live-фактов на CX-6 нет — для бёрна только после live-верификации);
  якоря крипто/burn-модуля и census — в JSON, калибровка — в журнале.
- **Lossy-рендеры дизасма** (asm→dis→asm не бит-экзакт; ассемблер
  канонизирует эмит, слова проверяются decode-verify по полям): полный
  реестр — `scripts/irisc/README.md`. Классы: q-form биты 0 и 2 (бит 0
  рендером не читается, офсет `& ~7` align-down), ld.d.17/st.d.1e бит 0,
  csr.w cf, csr.r rs + старшие биты imm, st.i биты 15..11, ld.i биты
  21..24, alu.0x* биты 9..10, mask32 биты 15..11, addi/addi.hi op-lsb
  (0x01→0x00, 0x03→0x02), shr funct 0x8a→0x83; roundtrip помечает их
  `fixpoint` (не DRIFT).

## Указатели

- `docs/250-re/120-irisc/` — кластер: эндианность/адреса (005), ISA (010),
  декодеры (015), Ghidra-пайплайн (020), boot-инъекция (025), детур CX-4 Lx
  (030–050).
- `docs/superpowers/specs/2026-10-15-irisc-asm-design.md` — дизайн.
- `scripts/irisc/profiles/` — JSON-профили (verified_on, census, якоря).
- `scripts/irisc/iRISC.slaspec` — канон мнемоник/рендеров, источник
  истины; Ghidra-контейнер печёт её в образ (canon-sync 2026-10-25),
  crosscheck-нога upstream монтирует нетронутую апстрим-копию
  (дрифт-контроль).
- `make irisc-crosscheck IMG=<bin>` — кросс-декодер-гейт Ghidra vs
  `irisc_dis` (отчёт в `build/`).

## Типичные ошибки

- Развёртывание 68B-фрейминга руками (копипаста из старых скриптов) —
  есть `clcrc_unwrap`/`clcrc_wrap`.
- Выводить энджианность/dc↔rt/CR-маппинг самому — блок конвенций выше.
- `cmp38` с другим sel «по аналогии» — funct5=0 ловит CPU в trap.
- `set3 rd,rd,imm` вместо `set3 rd,zero,imm` — получится OR, не запись.
- Ассемблировать без профиля для бёрна — strict-гейт именно за этим.
