# 015. Декодеры iRISC: канон, баг-фиксы, кросс-гейт

> Источник: `scripts/irisc/irisc_dis.py`, `scripts/irisc/enc.py`,
> `scripts/irisc/crosscheck.py` (+ golden `tests/test_irisc_dis.py`,
> `tests/test_irisc_enc.py`); провенанс-коммиты `1ead28a` (порт), `b49358c`,
> `efdbc90`, `591be5d`, `e8a66e0`, `25c9aa2`; журналы
> `docs/superpowers/journal/2026-09-23-irisc-isa-i2b-rosetta.md`,
> `docs/superpowers/journal/2026-09-23-irisc-isa-fuzz-task-08.md`,
> `docs/superpowers/journal/2026-09-24-irisc-ondemand-s2-task-19-debug2.md`.
> Связи: эндианность/адреса → `005-endian-addressing.md`; семантики ISA →
> `010-isa.md`; slaspec-канон и Ghidra-пайплайн → `020-ghidra-pipeline.md`;
> реестр lossy-рендеров и clcrc-API — `scripts/irisc/README.md`.

## 1. Канонические инструменты

- `scripts/irisc/irisc_dis.py` — канонический BE-декодер: `dis(w, off)`
  43-142, чтение файла `struct.unpack_from('>I')` :152; q-form-фикс — 86,
  116; branch-cc — 124-125.
- `scripts/irisc/enc.py` — verified word encoder, golden-тесты
  (`tests/test_irisc_enc.py`); провенанс: `b49358c` («verified word encoder
  with golden tests (jump off-by-4 fixed)»), `efdbc90` (s2 stub encoders).
  Для нового кода — ядро `scripts/irisc/irisc_asm.py` (ассемблер с
  decode-verify каждого слова + strict-профили; канон-слой/сахар/
  синдикат-диалект — `scripts/irisc/README.md`).
- Ad-hoc-копии — **НЕ поддерживаются** (порт `1ead28a`, исследовательские
  остатки): `scripts/s1/dec2.py`, `scripts/s1/dump.py`,
  `scripts/irisc/snips.py`. Использовать только канонические.

## 2. Баг-фиксы канонического декодера

(а) **branch cc selector** — cc = биты (16,20) branch-слова
(`irisc_dis.py:124-125`; slaspec `cmpop=(16,20)`). Фикс `591be5d` («branch
cc selector is bits 16-20 (golden b.t.eq64)»); corroborated
SHA-256-эмуляцией (i2b §5:118).

(b) **q-form EA (ops 0x17 ld.q.17 / 0x1e st.q.1e)** — фикс 2026-10-05
(commit `e8a66e0`: «irisc_dis: q-form (0x17/0x1e) EA is 8-byte align-down of
offset (I2-b)»; `irisc_dis.py:86,116` — `fmt(o & ~7)`). **Модель: EA-офсет =
8-байтовое выравнивание ОФСЕТА вниз; НЕ field-маска.** Proof —
SHA-256-эмуляция (i2b §3/§5): 8 сэмплов, 0x114→0x110 и 0x10c→0x108 (поля
f&7 = 5 и 3 — field-маска `&~7` дала бы 0x100 — опровергнута); 15 векторов
против hashlib. Slaspec-маска согласована с моделью: OFF14/STOREOFF14 уже
×4 (`iRISC.slaspec:158` `reloc = off14 << 2`, `:154` `reloc =
(storeoff_hi << 11) | (storeoff14_lo << 2)`), поэтому q-form-маска
`& 0xfffffff8` (slaspec 283-285 ld.q.17, 337-339 st.q.1e) — тот же
align-down. d/w-формы — БЕЗ маски (slaspec 279-281 ld.d.17, 291-296
ld.q/ld.d, 309-315 st.q/st.d, 322-329 st.q!/st.d!; разбор — журнал
task-19-debug2, Phase 2.2, 80-86). Реальное слово 4030 (SHA-256 init,
MAIN_CODE dc 0x2b1700): `0x78802914` → истинный EA `0x110` (до фикса
декодер печатал `st.q.1e r5,r4,0x114` — i2b:52 «→ lands at +0x110»).

Эрата 2026-10-15 (кросс-декодер-гейт irisc-asm, commit `25c9aa2`) — ещё
три бага `irisc_dis.py`, найдены гейтом `make irisc-crosscheck`, все
исправлены (+ golden `tests/test_irisc_dis.py`):

- (c) **mask32 shift-поле** — m читается из бит 5..10 (`(w>>5)&0x3f`,
  6 бит), не из 11..15; биты 11..15 — мусор (скан 7528 mask32-слов 4030:
  нулевые на 7511, ненулевые = data-джанк);
- (d) **`ands` imm — raw u16**, без знакового расширения (~550 сайтов
  4030);
- (e) **branch/jump-таргеты обрезаются до 32 бит** (`& 0xffffffff`; ops
  0x25/0x28–0x2b).

## 3. Расхождение источников (зафиксировано)

Шортхенд «q-form EA (ops 0x17/0x1e) −4» (формулировка roadmap до правки
2026-10-05; живой источник — TODO) — правило по 8 сэмплам (все ≡ 4 mod 8),
не эквивалентно align-down-модели (для офсета ≡ 0 mod 8 «−4» дал бы
неверный EA). Align-down — уточнение, зафиксированное I2-b-эмуляцией +
фиксом `e8a66e0`. Расхождение зафиксировано, не разрешено (историческая
формулировка в git-истории).

## 4. Кросс-декодер-гейт (Ghidra × irisc_dis)

`make irisc-crosscheck IMG=<fw-image>` (`scripts/irisc/crosscheck.py`;
`IRISC_CROSSCHECK_SLASPEC={repo,upstream,both}`, отчёт в `build/`):
линейно по всей MAIN_CODE (code+data) сравнивает headless-Ghidra
(контейнер — `020-ghidra-pipeline.md`) с `irisc_dis`; диффы
классифицируются {documented | outside_slaspec | data | decoder_bug};
**гейт = unclassified == 0 и decoder_bug == 0**. Прогоны: 2026-10-15 —
4030 CDA (941936 слов) и 1900-GCA (815872 слов), обе конфигурации slaspec
(repo + upstream пин 4c488a4) — PASS; canon-sync 2026-10-25 (repo-нога
outside_slaspec 15595 → 11960, upstream без изменений) и canon-sync
2026-11-01 (пара «наш `andmsk.hi` / upstream `or`» → documented) — PASS,
decoder_bug=0, unclassified=0.
