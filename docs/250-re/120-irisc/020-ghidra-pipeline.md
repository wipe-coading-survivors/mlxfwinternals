# 020. Ghidra-пайплайн iRISC: контейнер, пин, slaspec-канон

> Источник: containerfile Ghidra-образа (исторически
> `docker/ghidra-irisc.containerfile`; с commit `d9ca9b9` — канон в
> компаньоне `ghidra-container`, см. §1); журналы
> `docs/superpowers/journal/2026-09-23-irisc-isa-fuzz-task-08.md` (§6, §10);
> upstream-check 2026-10-05 (план «Verified facts»); провенанс slaspec —
> коммиты `1ead28a`, `4f4f7b3`.
> Связи: эндианность/адреса → `005-endian-addressing.md`; семантики ISA и
> мёрж-волны → `010-isa.md`; декодеры/кросс-гейт → `015-decoders.md`.

## 1. Контейнер и пины

Образ `mlxini-ghidra-irisc` (fedora:44, JDK21 `21.0.12.1+1`
sha256-pinned, Ghidra `12.1.3_PUBLIC_20260817` sha256-pinned):

- clone upstream `irisc-research-syndicate/ghidra-processor` **в образе**,
  `checkout --detach` на пине
  `4c488a43cdbcef957519e3800c3ba796712d3abb`, установка в
  `/opt/ghidra/Ghidra/Processors/iRISC/`; Sleigh-компиляция спеки в образе
  (SleighCompile).
- В образе лежит **upstream**-копия спеки, НЕ репо-копия (журнал task-08
  §6, 142-153).
- Slaspec из репо `scripts/irisc/iRISC.slaspec` — **каноничная рабочая
  копия**: маунтится в контейнер (file-mount поверх модуля) + дословная
  SleighCompile-команда; результат «1 languages successfully compiled»
  (журнал task-08 §6/§10).
- Upstream check 2026-10-05: `git ls-remote
  https://github.com/irisc-research-syndicate/ghidra-processor.git HEAD` =
  `4c488a43cdbcef957519e3800c3ba796712d3abb` = наш пин. Обновлений
  upstream нет.

**Текущая дислокация (актуализация 2026-11-07; slaspec — патч-как-канон,
2026-11-10):** контейнер и скрипты (`ghidra-irisc.containerfile`,
`ghidra-re.sh`, `ghidra-decode.sh`) канонизированы в приватном компаньоне
`ghidra-container` (`GHIDRA_CONTAINER_DIR ?= ../ghidra-container`,
`local.mk.example`); пины (fedora:44, JDK/Ghidra sha256, syndicate
`4c488a43…`) сверены с компаньоном — совпадают. Канон slaspec —
**патч** `scripts/irisc/iRISC.slaspec.patch` (tracked, живёт в mlxini;
заголовок: пин апстрима + sha256 апстрима + sha256 результата); полные
файлы — untracked-генерация `make slaspec-gen` (fetch/verify → apply →
verify; зависит каждая тест-цель Makefile; офлайн без кэша — warn,
integrity-отказ — fail); апстрим-копия для independence-прогона
кросс-гейта — `scripts/irisc/iRISC.upstream.slaspec` (pristine
fetched-байты, `015-decoders.md` §4).

## 2. Slaspec: канон и статус

- **Канон мнемоник/рендеров** — `iRISC.slaspec` (источник истины; канон
  ассемблера — скилл `irisc-asm`, локальная копия канона —
  `scripts/irisc/README.md`). Каноническая форма спеки — tracked-патч
  `scripts/irisc/iRISC.slaspec.patch` (дельта upstream@пин → канон,
  `make slaspec-gen`/`slaspec_patch.py regen`, см. §1); статус
  мёржей/семантик — карта `010-isa.md`, здесь не дублируется.
- **Provenance:** база — ghidra-processor iRISC Research Syndicate, пин
  `4c488a4`; порт в репо `1ead28a`; наш фикс `4f4f7b3` («irisc: slaspec
  cc0a consumer + cmp.w (op38) — live-proven») — три минимальные правки:
  1. модель регистра CMPRES @0x81008, size=1 (slaspec 57-59);
  2. `cc: "cmpres" is cmpop=0x0a { export CMPRES; }` (slaspec 173);
  3. `cmp.w RSsrc, RTsrc, imm11` op=0x38 cmpop=0x00:
     `CMPRES = (RSlosrc == RTlosrc)` (slaspec 361-363).
  cc-таблица синдиката **не содержит** селектора 0x0a. Дальнейшие
  мёрж-волны (`061d7e0`, `06be769`, `b33c058`, `f2a76c1`, `5987157`;
  +82 конструктора арки isa-max) — хронология и опоры в `010-isa.md` §3–§6.
- **Граница live-proven семантик** — per-op карта статусов `010-isa.md`
  (merged/live-only/static-verdict); публикация/лиценз-трек slaspec —
  `roadmap-restructure.md` §6 (отдельный трек, здесь не дублируется).
