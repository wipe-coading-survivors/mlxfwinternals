# 100-irisc

**Статус:** done
**Цель:** Единый план работ по iRISC (FW-CPU ConnectX-5 и CX-4 Lx): ISA-RE,
on-demand исполнение, тулинг, порт детура на CX-4 Lx, каналы возврата
результата (readback).
**Критерии закрытия:** по таблице «Критерии готовности» в конце тела
(I, II, III, IX–XII); фазы I0–XII, R-E/R-F закрыты — статусы в теле.
**Фазы/задачи:**
- S3-фоллоу-апы (Фаза II): RE delivery-транспорта (декод 0x2ae98/0x2a154 +
  X1-lookup 0x18a668; ICMC-miss-след, class/level сайта не установлен) и
  probe-команда через FN_A (достижение P, H2-широкий) — active
- S5 (Фаза II): персистентность (FNP flash vs RAM на-бут) + recovery — active
- Унификация декодеров (Фаза III): канон `scripts/irisc/irisc_dis.py`;
  `dec2.py`/`snips.py` — референсы; подключить s1-скрипты к канону — active
- Ghidra-контейнер (Фаза III): поддерживать канон-сласпек в образе
  в актуальном состоянии — active
**Семёна:** не TODO/ROADMAP-семя — самостоятельный roadmap-файл
`roadmap-irisc` (первый коммит `36c8f57`, 2026-09-23); суперседирует
планирование спеки `2026-09-22-irisc-ondemand-exec-read-design.md`.
**Связи:** кластер `docs/250-re/120-irisc/`
(005–050; преемник трёх исходников), `docs/750-exp/175-irisc-injection-burns.md`,
`docs/850-howto/190-irisc-build-burn.md`,
`docs/250-re/130-cable-gate/`, `TODO.md`; journals/reports/ledgers —
`docs/superpowers/`.

## ROADMAP-iRISC

Единый план работ по iRISC (FW-CPU ConnectX-5 **и CX-4 Lx**): ISA-RE
(расшифровка опкодов), on-demand исполнение (арка S0–S5), тулинг, порт
детура на CX-4 Lx (Фаза V), каналы возврата результата — чтение RAM по
методу синдиката (Фазы IX–XII). **Суперседирует планирование**
спеки `docs/superpowers/specs/2026-09-22-irisc-ondemand-exec-read-design.md`
(спека остаётся техдокументом по on-demand дизайну; её §6-разветвление
«runtime-локатор vs slaspec» закрывается этим роадмапом: **делаем оба**).

Контекст: `docs/250-re/120-irisc/025-boot-injection.md` (S0 PoC),
`docs/250-re/130-cable-gate/010-wall.md` (стена чтения iRISC с хоста), `TODO.md`.
Мелкие/отложенные задачи — `TODO.md`. Надцель (владелец, 2026-10-15):
понять secure_fw и снять его ограничения (мотивация: secure-карты дешевле
на вторичке); до отдельного `roadmap-secure-fw.md` все фазы идут на
**non-secure** прошивках — чтобы точно знать, что результатам не мешают
secure_fw-факторы.
Статусы: `[ ]` не начато · `[~]` в работе · `[x]` сделано (ссылка на результат).

Железо (не смешивать):

| Карта | PCI | Роль |
|---|---|---|
| CX-5 Ex (MT28800, жертвенная) | `81:00.0` | on-demand S1–S5 (S1 закрыта 2026-09-24, S2/C1 — 2026-10-02; FW-состояние/история — docs/250-re/100-formats/065-fw-trace.md) |
| CX-5 (MT27800, MCX512A-ACA_Ax_Bx, жертвенная) | `01:00.0` | **фаззинг-трек** (не мешает S1-сессии; владелец 2026-09-23) |
| CX-4 Lx (MT27710, MCX4131A-BCAT→GCA 14.32.1900, root-bazzite) | `04:00.0` | **Фаза V** — порт детура (docs/050-hardware/100-inventory; burns/ребуты bazzite не ограничены — владелец 2026-10-11) |

Правила: live-HW (burn/фаззинг/эксперименты) — только субагент + журнал
(AGENTS.md `live-hw-subagent`); рид-онли-проверки (`lspci`-класс) — можно
напрямую. FNP + IPMI-powercycle — recovery (креды не светить). CRC fixup
per-line clcrc — round-trip обязателен (PC4).

## Фаза I0 — базовая линия ISA — [x] (2026-09-23)

- [x] Sleigh-спека синдиката `iRISC.slaspec` (30 op из 64 + funct-ALU в
      0x3f; источник: irisc-research-syndicate/ghidra-processor, пин 4c488a4;
      копия в репо: `scripts/irisc/iRISC.slaspec`)
- [x] Метод синдиката (bornhack2024.pdf): layout-guess → Rosetta-stone
      (SHA-256 K-константы) → Sleigh → фаззинг на живой карте. Фаззинг-шаблоны:
      `refs/src/irisc-research-syndicate_mlx5cmd/shellcodes/test_*.asm`
      (`unk.i {{opcode}}, r7, r5, {{simm16}}` + дамп регистров)
- [x] Гистограмма op-полей по всему de-clcrc MAIN_CODE 4030 (журнал
      `2026-09-20-irisc-4030-qft-handler-re.md` §6) — **с включением data**
- [x] **Чистый пересчёт (code vs data)** — журнал
      `2026-09-23-irisc-unknown-ops-recount.md`. Итоговая база неизвестных:

| op | count (код) | Статус/инференс |
|----|------|---|
| 0x36 | 3774 | REAL: compare (rd=zero 98%, branch@+1..3 100%); `imm&0x1f` — вероятный cmpop-селектор (ГИПОТЕЗА) |
| 0x0d | 3393 | REAL: bit-field insert/extract (imm — mask-подобные 0x400–0xfe00) |
| 0x33 | 2115 | REAL: reg-reg bit-op |
| 0x34 | 1492 | REAL: reg-reg bit-op |
| 0x16 | 65 | REAL (rare): addr/index-хелпер (`0x16 rX,rY,zero imm` + immediate ld/st) |
| 0x1d | 32 | REAL (rare): compare-подобный (rd=zero 100%); 99.7% счёта §6 — одна data-таблица |
| 0x38 | 28 | REAL (rare): compare-вариант (rd=zero 96%) |
| 0x39/0x3c | 10/11 | REAL (rare) |
| 0x20/0x3a/0x2d/0x3b | 6/6/4/2 | probably-real |
| 0x22 | 1 | REAL: слово @0x22128 — цель branch (definitive) |
| 0x0f,0x10,0x11,0x14,0x15,0x1f,0x21,0x23,0x24,0x26,0x27,0x2c,0x2e,0x2f,0x30,0x31,0x35,0x37,0x3d,0x3e | strict=0 | NOISE (data; в §6 считались как опкоды) |

Код ≈ 87–90% бинаря; ~10–13% data (строки ~7–10%, таблицы ~3%, в т.ч.
289KB дескрипторная @0x3461e0; **SHA-256 K-таблица @0x3940a8** — Rosetta-якорь).
Неизвестных слов в коде ≈ 10939 из 941936 (~1.2%; полный счёт §6 с data —
21960, 2.33%).

Сюрпризы пересчёта: (1) половина «неизвестных» §6 — data; реальный фронт
~14 op, из них ядро — 4; (2) найдены **2 бага dis.py**: ветки 0x28–0x2b
считают цель как `(PC+4)+o*4`, правильно `PC+o*4` (Ghidra-верифицировано) +
известный §16 store-offset; (3) вывод: расшифровка опкодов — **меньше работы,
чем считалось** (большинство частотных «неизвестных» исчезли).

## Фаза I — ISA-RE: расшифровка неизвестных опкодов — [x] (2026-11-02)

*ЗАКРЫТА 2026-11-02, арка isa-max A+B по критерию «цель-максимум»: всё
раскалываемое в рамках правила 2-подтверждений смёржено, residual
зафиксированы; история: fuzz-5 завершён 2026-10-27, фоллбек владельцем
не принят — арка isa-max 2026-10-31/11-02.*

Цель: полная семантика ~14 реальных неизвестных op (+ cmpop-семантика 0x36),
слитая в slaspec. Критерий готовности: C1–C4 спеки-арки
`docs/superpowers/specs/2026-09-23-irisc-isa-re-design.md` (дизайн секций
I2–I5; план — на секцию, первый перед I3-burn). Дополнительно от C1:
de-компиляция core-регионов без unkBrCond-дыр на 0x36-идиомах.

**Constraint размещения (урок S1 v3-fail, журнал
`2026-09-23-irisc-ondemand-s1-v3-fail-re.md` §2.3/§6.1):** нулевые дыры
MAIN_CODE — живые данные-пулы; безопасен только доказанный префикс
(аналог 4030 0x38d730–0x38d7d8, 42 слова); перед I3-burn — верификация
`enc.py` (их §6.2 encoder-баг) и перепроверка scout-карты ACA8008.

Треки параллельны; порядок приоритета владелец утвердил 2026-09-23 (все).

- [x] **I1. Провизорный slaspec** — ЗАКРЫТО (2026-09-23, журнал
      `2026-09-23-irisc-slaspec-provisional.md`): предпосылка **опровергнута** —
      slaspec синдиката (пин 4c488a4, байт-идентичен /tmp-копии) уже содержит
      generic `unk.^op` catch-all; decode-gaps от неизвестных op невозможны
      (F_A/F_C декодируются полностью, включая unk-слова; ветка INTO unk-слово
      тоже). Реальный блокер xref — **flow coverage** (entry-reachable decode
      ~10%: косвенные переходы + один гигантский code0-блок), не опкоды.
      Остаточная ценность provisional-ентрис — display-only (отложено).
- [x] **I2. Статический grind** (offline, read-only, фоновые субагенты + журнал):
      - контексты per-op → def-use + compiler-идиомы;
      - **Rosetta-stones**: SHA-256 (K-таблица @0x3940a8 — найти
        sha256_transform, от него — идиомы сдвигов/поворотов);
        CRC16/CRC32 — референс per-line clcrc-реализации есть в `mlxfwutil`
        (`clcrc_calc`, `clcrc_unwrap`/`clcrc_wrap`; 68B-фрейминг), код
        точно есть в FW (FS4-verify path);
      - кросс-версионный diff: 16.19.1200 / 16.35.4030 / CX6-Dx 22.50 —
        один компилятор, идентичные функции → вывод layout'ов по рассинхрону;
      - пролог/эпилог-паттерны (метод синдиката).
  - [x] **I2-a (2026-09-23, журнал `2026-09-23-irisc-isa-i2a-op36-grind.md`):**
        `0x36 = CMP.W rs, rt, sel(bits16-20)` — compare-latch (sticky),
        потребляемый ветками **cc=0x0a** (второй механизм условий, независимый
        от N/Z/C/V флагов; селектора 0x0a нет в slaspec-таблице синдиката!).
        0x38 = тот же механизм, вероятно 64-битный вариант; **0x1d — НЕ
        compare** (семейство struct-walk с 0x16 — ревизия вердикта пересчёта).
        Векторы V1-V10 с точными словами — готовые входы для I3.
        **Live-обновление (2026-09-23, fuzz-1):** H-A опровергнута HW —
        все probes (V1/V2/V5) равномерно not-taken; 4-комбинационный перебор
        (операнд-источник × полярность) не выживает — гипотезное пространство
        сузилось до: cc0a≠cmp-consumer, init-зависимость, rd-гипотеза
        (ослаблена), V-flag-вариант H-C (журнал task-05 §2).
  - [x] **I2-b (2026-09-23, журнал `2026-09-23-irisc-isa-i2b-rosetta.md`):**
        SHA-256 suite найдена и **полностью эмулирована** (transform
        @0x2b13b0 + init/update/final; 15 векторов против hashlib — PASS):
        алгоритмически верифицированы BE-память, set0-3 (hw0=MSB), lw.r,
        st.d! post-inc, shrh, addi.hi, cc0/cc3. Внутри SHA-тела unknown-op
        нет. CRC-таблиц в image НЕТ (clcrc — host/HW-side). Найдены 2 бага
        декодера: q-form EA (ops 0x17/0x1e) — исправлен 2026-10-05
        (8-байтовое выравнивание офсета вниз; docs/250-re/120-irisc/015-decoders.md); branch-cc биты
        (исправлен, `591be5d`).
  - [x] **I2-c (2026-10-25, журнал `2026-10-25-irisc-isa-i2-bitops-grind.md` +
         WP-2 `…-wp2-c3-check.md`; отчёт `docs/superpowers/reports/
         irisc-isa-static-grind.md`):** I2-остаток закрыт — bit-ops grind
         0x0d/0x33/0x34 (def-use, кластеры, кросс-версии 4030/8008/16.19.1200/
         14.32/CX6Dx). Главная находка — **Rosetta-пара 4030↔16.19.1200**
         (dc 0x08c124↔0x057514, score 31/32): `0x34 f5=2 = and ~(1<<idx)`
         (первое кросс-версионно-доказанное); lo11 0x33/0x34 =
         flag\|idx\|f5; ревизия «известного» 0x0c (or-imm → вероятно ANDN,
         live-векторы готовы); 0x33/0x34/0x36 — поздние опкоды (1619: 0x34
         = 0 сайтов). **C2**: C2-вердикты по всем редким op (0x16/0x1d
         struct-walk; 0x3c limit-compare — 1 вектор; 0x39 опц.; 0x3a/0x20/
         0x2d/0x3b — не влияет; live-пробы по возможности — WP-3). **C3
         закрыт**: 0 unkBrCond на 9/9 core/0x36-плотных функциях с канон-
         спекой `4f4f7b3` (до фикса 15+2); 0x36-продюсер = void-call UnkOp,
         семантика для декомпиляции не нужна. 25 live-векторов (decode-
         verify, sentinel-контроль) — готовый вход fuzz-4/I4; irisc-
         crosscheck PASS.
   - [x] **I3. Фаззинг через S0** (live, карта `01:00.0` MCX512A) —
      **план `docs/superpowers/plans/2026-09-23-irisc-isa-fuzz.md`**
      (T1 энкодер-golden → T2 safe-zone → T3 образ#1 (маркер + probes
      V1-V3) → T4 burn+VSEC-read [live] → T5 вердикт 0x36/cc0a +
      slaspec-кандидат + handoff S1). Boot-injection
      PoC (docs/250-re/120-irisc/025-boot-injection.md) как executor — шаблоны синдиката `test_unki.asm`
      адаптировать под result-channel CR (st.d → host-CR слот, чтение VSEC).
      1 эксперимент = 1 reflash+boot; known-good сток + FNP-recovery. Первые
      цели: 0x36 (валидация cmpop-гипотезы), 0x0d/0x33/0x34 (bit-ops),
      затем редкие. Тест-векторы: as в syndicate-стиле (пары входов + edge:
      нули, единицы, знаковые, шифты 0/31/32/63).
  - [x] I3 pre-flight scout (2026-09-23, журнал
        `2026-09-23-irisc-fuzz-target-scout.md`): образ **ACA8008** (16.35.8008,
        md5 `7dce1484…`), ISA-профиль ≈ 4030 (core-4 в пределах 1%); landmarks:
        инъекция **dc 0x1d5b8** (слово `940002de` бит-идентично 4030!),
        cave **0x38e2c0..0x38e778** (1208B), result-CR **0x23f0 тот же**
        (unlock-leaf @0x107dd8). Открыто: VSEC base на MCX512A (probe live).
        Next: burn + маркер (live, субагент).
  - [x] **I3 итерация 1 = fuzz-1** (2026-09-23, журналы task-03/04/05):
        образ собран (enc+clcrc round-trip), сожжён, **конвейер
        4030→8008/MT27800 доказан end-to-end** (инъекция dc 0x1d5b8 →
        32-словный шеллкод → маркер 0x23f0 = 0xbadc0001 → VSEC-чтение
        base 0xc0); повторный burn допустим (known-good rollback: сток
        ACA8008). Результат по 0x36/cc0a — **отрицательный**: все probes
        (V1/V2/V5) not-taken; ограничение: known-taken контроль
        отсутствовал (taken-путь ветки не был доказан — зафиксировано).
  - [x] **I3 итерация 2 = fuzz-2** (2026-09-23, журналы task-05/06/07/08):
        образ с GUID-инжектом сожжён, boot healthy, netdev MAC жив (zero-MAC
        закрыт). **Главный результат: op 0x38 = CMP.W → cc0a-latch —
        live-подтверждено (P2: eq32 с 32-битным усечением, taken); 0x36 ≠
        compare** (наша форма не ставит вход cc0a: P1/P3 not-taken при
        прошедших контролях C1/C2 → H-A/H-B/polarity/G/sel-ось/операнд-модели
        0x36 мертвы). Slaspec-кандидат закоммичен: cc=0x0a consumer
        (b.t/b.f.cmpres) + `cmp.w` op38 (Sleigh-компиляция + decode-чек —
        журнал task-08 §5-6). Открытое (fuzz-3) — закрыто fuzz-3
        (2026-10-06, task-03): идентичность 0x36 → cc0a-продусер
        (predicate-compare, f5-карта); cmpxchg/fld-fst store-направление и
        F-контекст — мертвы; COUNTER=0x9 → live-факты + гипотеза. (q-form
        EA декодер-баг — закрыт 2026-10-05: docs/250-re/120-irisc/015-decoders.md.)
   - [x] **I3 итерация 3 = fuzz-3** (2026-10-05/06, журналы task-01/02/03 +
         дизайн `2026-10-05-fuzz3-vector-design.md`; два burn'а: A — идентичность
         0x36, B′ — ширина cmp.w + sel): **0x36 КОРМИТ cc0a — predicate-
         compare** (первые taken S1/S-V, первый активный F S3 — flip-проверено;
         вердикт fuzz-2 «0x36 ≠ compare» уточнён: формы fuzz-2 дали F на своих
         операндах). f5=2 (i6=0) → signed lt (16/32) или V-флаг (ne32/eq32/
         gt32 мертвы на P1/C2); f5=4 → T(0,0), f5=0xa → F(5,5) — живые,
         неопределены (одна точка); imm6-форма (S2, i6=32) — open; S-M: store-
         эффекта нет. **cmp.w: eq32 подтверждена** (P2 исключает 64/hi32, W2a —
         eq16, W2b — hi16; совпадает со slaspec CMPRES `4f4f7b3` — slaspec не
         менялся). **Sel-ось мертва** (X1=W0 на тех же операндах). Self→FALSE
         (C1×2, P3 flip-proven) — slaspec-кандидат (2 подтверждения: 1 метод).
         COUNTER: baseline 9 персистентна (2 power cycle), дельты ≠ числу
         DATA-read; self-read-гипотеза + рецепт дешёвой live-верификации.
          Открыто (fuzz-4/I4): f5-карта 0x36, lt-vs-V-дискриминатор, imm6-форма,
          COUNTER-семантика, load/E-rd.
   - [x] **I3 итерация 4 = fuzz-4** (2026-10-25, спека `2026-10-25-irisc-
          fuzz4-design.md`, план `…-fuzz4.md`, SDD 8 задач; отчёт
          `docs/superpowers/reports/irisc-fuzz4.md`; журналы
          `2026-10-25-irisc-fuzz4-task-01..07.md`): **on-demand exec на
          late-site 0x0E43C4 live-доказан и отработал массово** — 24/24
          векторов, 48 запусков, 0 wedge, смена вектора без reflash
          (payload QUERY input[0x18..0x40), trampoline 3 сл @0x38d774,
          образ `irisc-fuzz4-v1.bin` md5 `a8072117…`; активация
          mstfwreset без ребута). Батарея: 61 строка — жива 26 / мертва
          35. **Slaspec-мёрж (2-подтверждения live×static): `and.hi`
          op=0x0d (`RDlo = RSlosrc & (imm16<<16)`, H-0d-A закрыта) и
          `bclr.1` op=0x34 lo11=0x022** (idx-генерализация live-опровержена
          — Rosetta-сайт единственный). **H-0c-ANDN live-опровержен**;
          eq32/eq16 — неразрешённый класс (неразделяющие векторы);
          lt32-запись подтверждена (ltV-семейство без мёржа — нужен
          known-T предшественник); COUNTER: **self-read подтверждён**
          (+1/чтение; «8+n» мертва). Live-факты: сток-Q(created) без
          resume-хвоста = wedge; post-battery wedge irisc 10 @0xb8d758 —
          открытое расследование. Карта 81:00.0 остаётся на fuzz-образе
          (владелец).
   - [x] **I3 итерация 5 = fuzz-5** (2026-10-26/27, финальный запланированный цикл фазы I /
          WP-4; спека `2026-10-26-irisc-fuzz5-design.md`, план `…-fuzz5.md`;
          отчёт `docs/superpowers/reports/irisc-fuzz5.md`; журналы
          `2026-10-26-irisc-fuzz5-task-01..06.md`; без burn — та же
          on-demand-батарея на fuzz-4 образе, рулинг односессионной
          батареи `310ee1c` после подтверждения wedge №2-класса в T3
          stop-rule): **census полной селекторной карты** (1250 строк × 5
          версий FW, 7 санити-гейтов) + батарея **142/142 + 11
          дискриминаторов** (237 жива/773 мертва/0 неопределена + 1 DIV;
          141 census-строка live-covered, design-required 133/133) +
          программный live×static мёрж-отбор (`select_merges.json`).
          **Slaspec-мёрж (2-подтверждения): конструктор `:dep` op=0x33**
          (replace-депозит поля W=f5 @idx, flag=0; 12 confirm-строк
          f5∈{1,4,8}, замкнул H-33-bit/H-33-dep-R) и **семантика op=0x0c
          H-0c-hi-and** (`rd_lo = rs_lo & ((imm16<<16)|0xffff)`);
          crosscheck decoder_bug=0/unclassified=0. eq16/eq32 **разрешён**
          (f5=4 → eq32); f5=2/f5=0xa → V; rogue-класс 0x34 (P-таблица)
          и 0x36 (вся ось — нет статической опоры) — open-остатки карты
          (docs/250-re/120-irisc/010-isa.md); H-16-shr конфликт imm=000; 0x39/0x3c double-live.
           **Цикл fuzz-5 завершён; фаза I продолжается** (владелец
           2026-10-26: цель-максимум, фоллбек не принят) — см. блок
           итога ниже.
   - [x] **I3 итерация 6 = isa-max-a** (2026-11-01, цикл A арки
           «цель-максимум», офлайн; спека
           `2026-10-31-irisc-isa-max-design.md`, план `…-isa-max-a.md`;
           отчёт `docs/superpowers/reports/irisc-isa-max-a.md`; журналы
           `2026-11-01-irisc-isa-max-a-task-01..09.md`; live-карта не
           трогалась): корпус-экспансия (129 ITOC-секций × 5 образов,
           32 iRISC; census 5799 строк, 71692 сайтов; редкие опы
           0x39 +1375% / 0x3c +988% strict) + нормализованный live-слой
           `fuzz5_live.json` (1255 записей) + стат-дожим: 0x36 —
           family-grade опора H-36-eq-usage (20 осей, 4668 eq-пар);
           0x34 — P-формула (52/52 captured, model_form=formula);
           H-16-shr — конфликт imm=000 снят (width32 + carve-out);
           0x39/0x3c — consistency-статика; cmp38-self — formalizable=FALSE
           (оба strict-сайта consumer-sensitive) → residual. **Мёрж-волна
           A: 34 конструктора** (`:cmp36.eq32` — первая семантика 0x36;
           `:dep.c`×26 P-литералов; `:shr32u.z`×4; `:mv.lo`×2; `:zero`)
           + **canon-sync `andmsk.hi`** (op 0x0c imm-форма, полный канон;
           upstream documented +7035 — прогноз fuzz5). Гейты: Sleigh PASS,
           crosscheck decoder_bug=0/unclassified=0, test-parallel 1426/1
           skip. Residual-манифест C-A.6 (отчёт) — вход плана B: 0x36
           live-multi 34 строки (5-модельный класс + f5=1 + imm6) + оси
           f5=2/0xa (H-V vs eq-семья), 0x34 rt-fed 49 + OPEN f5=2 idx=5,
           0x38 sel=4 повторы + cmp38-self — инвариант B: corroborating
           0x33 f5=0x0f + повторный мёрж-отбор. Карта — docs/250-re/120-irisc/010-isa.md.
           **Цикл A закрыт; фаза I: остался live-цикл B** (план — от
            residual-манифеста после final-review A).
    - [x] **I3 итерация 7 = isa-max-b** (2026-11-02, цикл B арки
            «цель-максимум», live; спека
            `2026-10-31-irisc-isa-max-design.md` (+дополнение
            2026-11-02), план `…-isa-max-b.md` (+plan-fix `da7b297` —
            расширение T4 под bclr.1 canon-sync); отчёт
            `docs/superpowers/reports/irisc-isa-max-b.md`; журналы
            `2026-11-02-irisc-isa-max-b-task-01..05.md`; карта
            `81:00.0` на fuzz-4 образе, без burn, owner-GO):
            **односессионная батарея 206/206 векторов ~11.8 мин**
            (identity 4/4 до/после, маркеры 412/412, **wedge=none —
            чистый финальный rebind впервые за циклы, recovery=0**,
            срезов/дозапусков не потребовалось). **map36: полный обход
            36 осей, 36/36 разделены** — выжили H-V ×29 / H-lt16 ×1 /
            H-ne32i ×6; eq-семья мертва на всех осях → мёржей 0:
            14 осей excluded.conflict (live V/ne32i vs статическая
            eq-семья — usage-vs-semantics, рамка владельцу в отчёте),
            22 live-only parked. **rtfed34 49/49 закрыты** (P-формула
            согласована со всеми наблюдениями ∧ rt-инвариант live) →
            **мёрж-волна B: 48 конструкторов** (`:dep.c` ×46 вкл. слот
            0x022 — снятие `bclr.1` canon-sync'ом 13 файлов: старое
            `& ~2` live-опровергнуто парой X/Y, маска 0x6; `:zero` ×2
            0x3c/{000,400} — lo11=000 переносом под
            литерал-униформностью). Инварианты: 0x33 f5=0x0f
            corroborating **PASSED** (live-only parked); 0x38 sel=4
            **CONVERGED** — детерминированный счётчик сессии +3 mod 8
            на tool-op, 35/35 (время/DIV опровергнуты), семантика —
            residual; cmp38-self — H-38self-false live ×3,
            formalizable=FALSE остаётся. Гейты: Sleigh PASS, crosscheck
            decoder_bug=0/unclassified=0 (волна 566 слов вне
            slaspec-класс, fix — 1 слово, upstream без изменений),
            test-parallel 1267/230. **Цикл B закрыт; арка isa-max
            закрыта** (+82 конструктора за арку; residual
            зафиксированы per-axis — фоллбэк-критерий спеки §1 без
            ослабления правила 2-подтверждений); карта — docs/250-re/120-irisc/010-isa.md.
            См. блок «Итог арки isa-max» ниже.

- [x] **I4. Фаззинг через S1 on-demand** — ЗАКРЫТО (2026-10-25, итерация
       fuzz-4, I3 выше): быстрый цикл без reflash реализован и отработан
       (fuzzvec-режим `crates/mlxscope`: VSEC-посев + sentinel
       0xdeadbeef + 40B payload + двухканальный verify out_mb/CR;
       вектор-артефакты `scripts/probes/cx5-fuzz4/`). Режим B (payload-
       канал ответа S2b/S4) не потребовался — двухканальный verify
       (echo-зона ответа + CR-readback) закрыл цикл возврата. Остатки
       (eq16/eq32-дискриминация, ltV known-T, 0x0c-гипотеза, cmp38-self) —
       следующие итерации того же конвейера (без нового образа).
- [x] **I5. Слияние и фиксация** (2026-10-05): семантика → slaspec —
      канон `scripts/irisc/iRISC.slaspec` (port `1ead28a`; live-proven
      подмножество: cc0a-consumer + cmp.w op38 sel=eq32 + регистр-модель
      CMPRES — `4f4f7b3`); остальное (0x36, sel≠0 у 0x38, lo11) — в slaspec
      по мере fuzz-3/grind. q-form EA декодер-баг — исправлен в
      `irisc_dis.py` (8-байтовое выравнивание офсета вниз; slaspec-маска
      согласована — OFF14/STOREOFF14 уже ×4). Номерной док:
      `docs/250-re/120-irisc/005-endian-addressing.md` (BE-файл/LE-адреса) и
      `docs/250-re/120-irisc/010-isa.md` (установленные
      факты). Апстрим ghidra-processor — проверен (2026-10-05,
      `git ls-remote`): HEAD = пин `4c488a4`, обновлений нет.

### Итог цикла fuzz-5 (2026-10-27; фаза I продолжается — владелец 2026-10-26: цель-максимум, фоллбек не принят; карта — docs/250-re/120-irisc/010-isa.md)

**Статус: цикл fuzz-5 завершён; фаза I продолжается (владелец
2026-10-26: цель-максимум, фоллбек «достаточно для потребителей» не
принят); open-остатки = скоуп следующего цикла (список ниже).**
Фоллбек-покрытие достигнуто (все has-sites классы live-верифицированы,
5 конструкторов смёржено) — потребительские критерии выполнены:
MAIN_CODE декодируется без decode-gaps (unk-catch-all + 6 смёрженных
семантик за фазу: cc0a-consumer, cmp.w eq32, and.hi, bclr.1, :dep 0x33,
0x0c-hi-and — `4f4f7b3`/`061d7e0`/`06be769`); per-op учёт — census 1250
строк + программный мёрж-отбор (audit trail) + итоговая карта.

Вердикты против критериев спеки ISA-RE (C1–C4, построчно):

- **C1 core-4** — частично: **0x0d ✅** (and.hi), **0x33 ✅** (:dep flag=0,
  вся ось live-корроборирована, 0 контрпримеров); **0x34 ⚠️** — смёржен
  только bclr.1 (единственный lo11-класс с сайтом), dep-класс live-разделён
  но мёрж заблокирован rogue-конфликтом статпривязки, rogue-класс
  (большинство f5, has-sites) — семантика open (P-таблица); **0x36 ❌ по
  slaspec-ноге** — live-карта всей f5-оси (разведены f5=4→eq32, f5=2→V,
  f5=0xa→V; прочие — неразведённый 5-модельный класс), мёржа нет: у 0x36
  нет статической опоры (правило 2-подтверждений — структурный потолок,
  фоллбек-строка (1) спеки fuzz-5).
- **C2 редкие (10 op)** — выполнен построчно: семантика — 0x16 (shr32u
  live; мёрж-конфликт imm=000 → переформулировка next-cycle), 0x38 sel=0
  (merged; value-forms «не-cc-writer»/DIV/непробируемы), 0x39
  (lo-passthrough, double-live), 0x3c (zero, double-live); верифицированный
  «не влияет» — 0x1d/0x20/0x3a/0x2d/0x3b; 0x22 закрыт ранее.
- **C3** — закрыт ранее (WP-2, 2026-10-25: 0 unkBrCond на 9/9
  core/0x36-плотных функциях).
- **C4** — закрыт: slaspec-мёржи в репо, per-op учёт (census_map.json +
  select_merges.json + карта), номера доков согласованы (аддендум
  docs/250-re/120-irisc/010-isa.md, новых номеров нет).

**Open-остатки = скоуп следующего цикла (владелец 2026-10-26:
цель-максимум):** 0x36-продюсер статическая опора (Rosetta-контексты/
I2-метод) + разведение 5-модельного класса (вкл. eq16/eq32-хвост
неразведённых f5-осей — сам класс разрешён на f5=4); 0x34 rogue
P-таблица (4 disc-точки) + corroborating-проба 0x33 f5=0x0f; H-16-shr
конфликт lo11=000 (переформулировка: ширина 32 + imm=0 carve-out);
0x38 sel=4 (волатильное поле); canon-sync 0x0c-мнемоники. Прочее из
рекомендаций T5/T6: cmp38-self→F формализация; wedge №2 @0xb8d758
(вне фаззинга).

### Итог арки isa-max (2026-11-02; циклы A+B; фаза I ЗАКРЫТА по критерию арки)

**Статус: арка «цель-максимум» закрыта** (спека §1: успех = «всё
раскалываемое в рамках правила 2-подтверждений смёржено, residual
зафиксированы» — решение владельца 2026-10-31). За арку +82 конструктора
в slaspec (A 34 + B 48) + canon-sync `andmsk.hi` (A) и `bclr.1`→`:dep.c
lo11=0x022` (B, live-опровержение `& ~2`, маска 0x6). Правило
2-подтверждений выдержано без ослаблений (single_method 0 в отборе B).
Карта — docs/250-re/120-irisc/010-isa.md (аддендумы A/B); полный residual-реестр — отчёт
`docs/superpowers/reports/irisc-isa-max-b.md`.

Вердикты против критериев спеки ISA-RE (обновление строк C1–C4 по
итогу арки; построчная история fuzz-5 — блок выше):

- **C1 core-4** — **0x0d ✅** (`and.hi`); **0x33 ✅** (`:dep` flag=0;
  corroborating-проба B f5=0x0f PASSED); **0x34 ✅ в пределах
  P-формулы** — 72 lo11-литерала `:dep.c` (A 26 + B 46), rt-fed
  residual 49/49 закрыт live-инвариантом (rt=X/Y пары батареи B);
  остатки-строки карты: OPEN f5=2 idx=5 (рулинг «не трогать»), mmio
  f5=1b (без rd-формулы); **0x36 — предел правила**: MAIN f5=4 смёржен
  `:cmp36.eq32` (A); полный live-обход B (36/36 осей разделены: H-V ×29
  / H-lt16 ×1 / H-ne32i ×6; eq-семья мертва на всех осях) → 14
  excluded.conflict (статическая eq-семья H-36-eq-usage против live —
  usage-vs-semantics) + 22 live-only parked — residual без нарушения
  правила; вопрос открытия канон-работы по напряжению — за владельцем
  (рамка в отчёте B).
- **C2 редкие (10 op)** — выполнен построчно и закрыт: 0x16
  (`:shr32u.z` ×4, A), 0x38 sel=0 merged / sel=4 — характер поля
  определён (детерминированный счётчик сессии +3 mod 8 на tool-op,
  35/35, B; семантика оси open — residual с массивом наблюдений) /
  cmp38-self formalizable=FALSE (residual, канон double-live ×3) /
  sel∈{1,20} непробируемы (структурный потолок), 0x39 (`:mv.lo` ×2, A),
  0x3c (`:zero` ×3: 7ff — A, 000/400 — B; lo11=001 live-only);
  «не влияет» — 0x1d/0x20/0x3a/0x2d/0x3b; 0x22 закрыт ранее.
- **C3/C4** — без изменений (закрыты ранее; per-op учёт дополнен
  select_merges_b.json).

**Фаза I закрыта.** Live-карта `81:00.0` освобождена из-под эксклюзива
арки (образ fuzz-4 не менялся, burn не выполнялся).

- 2026-11-09: полный rerun батареи корпуса isa-max-B новым бинарем
  `mlxscope` (post-mlxdirect CMDQ, post-rename; md5 `9ba72c7f…`) —
  206/206, 661/661 verdicts+observed байт-в-байт == isa-max-B, маркеры
  412/412, wedge=none/recovery=0; отчёт
  `docs/superpowers/reports/mlxscope-battery.md`.

## Фаза II — On-demand исполнение (арка S0–S5, по спеке) — [~]

Спека: `2026-09-22-irisc-ondemand-exec-read-design.md` (критерии C1–C4,
риски, pre-check PC1–PC4 — выполнены). Зависимости: `S0 → S1 → S2 → {S3,S4} → S5`.

- [x] **S0** — boot-detour + host-CR канал (docs/250-re/120-irisc/025-boot-injection.md; маркер 0xbadc0001,
      injection dc 0x1d594 → shellcode dc 0x38d730)
- [x] **S1** — локализация потока 0x0932 — ЗАКРЫТО (2026-09-24, отчёт
      `docs/superpowers/reports/irisc-ondemand-s1.md`; детали — ledger
      `docs/superpowers/ledgers/irisc-ondemand-s1.progress.md`). Дизайн
      two-part (pre-hook + кандидатный набор) заменён прямым capture:
      хук FN_A @0x18d964 → стаб @0x38d770 → exfil `ra` в CR 0x2380–0x2390
      (v2-guided → v4d no-op (root cause слота 0x38d770 подтверждён A/B)
      → v4e capture `662f593e…`). **G5: поток 0x0932 = call-сайт 0x0e437c
      / fn [0x0e4250..0x0e4424)** (QUERY BadParam-path; success-path
      триггером недостижим на 16.35.4030 — Qcreated всегда 0x1c2b78).
      Бонус-факты: live-PC = file-offset + 0x800000; 22 call-сайта FN_A
      подтверждены live+xref. Рабочий примитив «эксперимент без reflash»:
      burn v4e → VFIO-trigger → VSEC-read (в т.ч. для S2).
- [x] **S2** — патч handler'а 0x0932 — ЗАКРЫТО: **C1 достигнут полностью**
      (2026-10-02, v5l live; отчёт `docs/superpowers/reports/
      irisc-ondemand-s2.md`, ledger-архив `docs/superpowers/ledgers/
      2026-09-24-irisc-ondemand-s2.md`). On-demand исполнение host-payload
      через детур call-сайта 0x0e437c: magic-фильтр (MAGIC16 @input[0x12],
      слот [r1+0xaa]) → no-link передача `ret.r zero,r8,r11` на payload
      В input-зоне посадки ([r1+0xac]) → маркер S2OK → CR 0x2388 =
      0x53324F4B точно → возврат по call-site resume 0x8E4380 в тело fn →
      **штатный completion** (status=0, syndrome=0x0; идемпотентно, хост
      жив). Линейка v1→v5l: 17 образов, 16 прожигов (v3 не прошивался);
      сага фризов (9 host-freeze на v5b–v5h) обойдена классом «ноль
      доп-записей в пуш-кадр» — механизм фризов (хвост-кадр × доп-записи;
      контент/счёт/петля не разделены) остаётся открытым исследованием.
      Откат-цепочка на сервере не тронута.
      **S2b/S2b-2 (payload-канал ответа, 2026-10-02→05) — канал НЕ
      закрыт: маркер не сел в host-памяти; следующий шаг = диагностика
      триггера (S3).** Механизм: стаб-хвост зовёт сток WRITE-POST — m2
      (0x18064c, v5m) → ruling m2′ (X1 = 0x8FC0|IOVA строится в стабе,
      прямой вызов 0x2ae98; v5n/v5o — byte-identity, md5 `b91848dc…`).
      Live: completion штатный (status=0/0x0), CR-эхо точный
      двухканально, маркер отсутствует — сначала в наблюдаемых окнах
      (v5m outbox, v5n out_mb0, v5o in_mb0), затем по всему 256 MiB
      (live-проб: обе байтовые формы, raw-дамп `dad13fdd…`, единственный
      хит = SELF-стейджинг, исключён) + 0 IOMMU-fault (формально
      верифицировано) ⇒ **DMA не выполнялась вообще** (false-negative
      исключён). RE-вердикт (iii): X1-форма верна (сток
      F|(v<<6)|0x8FC0), не хватает X: маппинг 0x8FC0→host-IOVA =
      SoC-level (не offline-разрешим), m2′ частична по F-члену (сток
      F≠0), триггер sync/async (doorbell csr0x34; engine-status —
      device-local, host-невидим — docs/250-re/120-irisc/025-boot-injection.md «стена»). 6 закрытых циклов
      — планы `2026-10-02-irisc-s2b-mode-b`, `2026-10-02-irisc-s2b2-
      {diag,v5n}`, `2026-10-03-irisc-s2b2-v5o`, `2026-10-04-irisc-
      s2b2-{post-window-x1-re, live-probe-wide-dump}`. Канонические
      документы: спека `2026-10-02-irisc-s2b2-delivery-design.md`
      (аддендумы 1–4, А–Г) + отчёт `docs/superpowers/reports/
      irisc-s2b2-live-probe-wide-dump.md` + ledger/журналы циклов
      (docs/superpowers/). Карта 81:00.0 на v5o(=v5n), здорова;
      mlxscope рекувирован в `crates/`.
- [ ] **S3** — триггер: хост шлёт 0x0932(payload) → on-demand exec —
      **цикл закрыт (2026-10-05→06), вердикт H4 (кандидат): маркер не сел
      из-за сбоя доставки POST стаба (X1-miss), не clobber стоком.** Цель —
      локализовать, почему iRISC→host DMA-маркер POST (из стаба
      0x2ae98/0x2a154) не приземляется в 256 MiB host-окно; лестница
      гипотез H1 (F-член) / H2-узкий (сток-тело) / H2-широкий (ленивый
      engine после CQE-GO) / H4 (иное: доставка). Лестница
      T1→T2→T2b→RE-c→v5r→T3→RE исчерпана: **H1 мёртв** (T2: F=0x40 не
      помогло), **H2-узкий мёртв** (T2b: сток-тело вне подозрения —
      body-exonerated), **H2-широкий НЕ проверен** (T3 невалиден — поздняя
      точка P=0x0E43C4 структурно недостижима для 0x0932: стоковый
      `call FN_A` (0x18D964) на 0x0E437C отклоняет кадр content-
      independently → error-exit (0x0E4388 `b.f.0x0` → эпилог 0x0E42E4 →
      0x0E430C `ret.r`) **ДО** CQE-POST (0x0E43B8) и **ДО** P). **Ключевой
      факт:** стоковой инструкции, пишущей в 0x18000040, **нет** —
      командный блок iRISC B (frame 0xF8 обёртки 0x0E4250) лежит в
      локальной RAM iRISC, а не в BAR2-окне (доказано дампом T3: собранный
      кадр w3w4 `00040000 00005332` нигде в 256 MiB; outbox в inline
      output cmd+0x20; out_mb нули) ⇒ отсутствие маркера в валидных пробах
      (T2/T2b) = сбой доставки POST стаба (**X1-miss**, delivery-spec §2:
      (a) lookup-miss → POST в мусор / (b) X1 = собственный блок команды),
      не clobber.       **Новая trace-сигнатура H4 (2026-10-09, mstfwtrace-цикл, docs/250-re/100-formats/065-fw-trace.md
      + journal `2026-10-09-itrace-flr-mask-experiment.md`):** в окне
      пробы на v5q iTrace ловит **`icmc fw dummy response,
      miss va=0x8fc018000040`** — низкие 32 бита va = адрес POST-маркера
      (0x18000040); событие v5q-only (на v5r его нет), привязано к моменту
      POST-попытки stub'a ⇒ прямой след ICMC-miss на доставку POST —
      усиливает фоллоу-ап (а). **icmc-сайт: class/level не установлен**
      (L0-цикл Task 1 (e): эмиттер вне MAIN_CODE — ROM/iron, строка в db1;
      виден под маской ICMD/-l 1 — либо ICMD-класс, либо L>=2-bypass) и
      **не зафиксирован под L0-маской `0x5000020 -l 0` (overflow)**
      (docs/250-re/100-formats/065-fw-trace.md) — **H4-след остаётся открытым**.
      Заодно: FLR/VFIO-окно НЕ сбрасывает iTrace-маску (H1-trace
      опровергнута; рецепт: маркер-верификация до окна); **L0-след
      (CMD_IF/STEERING) закрыт (L0-цикл 2026-10-09, docs/250-re/100-formats/065-fw-trace.md)**:
      command-path пробы трассирован под `-m 0x5000020 -l 0` — v5r:
      FN_A W6 `0x18da3c` (syndrome 0x31c2b78, stock BadParameter-path) +
      `cmdif_driver cmd_failure opcode=0x0932` пойманы; v5q: FN_A
      обходится stub'ом (DONE + S2OK); icmd-события пробы нет (оба
      образа) — дискриминирующая пара подтверждена live (журналы
      `2026-10-09-irisc-itrace-l0-trace-task-0{1,2,3}.md` +
      `2026-10-09-irisc-itrace-v5r-nodata.md`).
      **Фоллоу-апы (следующая сессия, спеки/планы отдельно;
      решение владельца 2026-10-06):** (а) RE-цикл по delivery-транспорту
      (декод 0x2ae98/0x2a154 + X1-lookup **0x18a668** — почему fire-and-
      forget DMA не приземляется; sync/async; валидность X1-цели/F-член;
      + ICMC-miss-след 2026-10-09); (б) найти probe-команду, проходящую
      FN_A (декод 0x29740/0x90C34 / другой opcode) — чтобы P стала
      достижимой и реально проверить H2-широкий (v5r late-detour — карта
      уже на v5r после L0-цикла, burn не нужен, + run). План
      `2026-10-05-irisc-s3-trigger-probe`, спека `…-design.md`; канон:
      **Аддендум 5 (Г.7)** delivery-spec + отчёт
      `docs/superpowers/reports/irisc-s3-trigger-probe.md` + ledger
      `…/ledgers/irisc-s3-trigger-probe.progress.md` + журналы
      `…/journal/2026-10-05-irisc-s3-trigger-probe-task-01..12.md`.
      Аномалия (вне плана): normal-mode flash-cache burn роняет хост (v5r:
      power-off 37% write → brick → FNP/cr-space recovery); надёжный путь =
      **FNP/cr-space** (v5r сожжён так, чисто) → TODO (расследование).
      Карта 81:00.0 на **v5r** (бёрн 2026-10-09 16:41, L0-цикл,
      normal-mode `--no_fw_ctrl`, GO владельца; ri==v5r verified, body
      0 diff; откат на v5q: источник `/root/v5q-ref.bin` md5 `7a796ad7…` +
      бэкап-дамп `/root/pre-burn-v5q-202610091552.bin` md5 `3572ea72…`;
      v5r-бэкап-дамп `/root/pre-burn-v5r-202610090615.bin` md5
      `919cb05e…`), normal mode, здорова; mlxscope в `crates/`.
      Сравнительная трасса (STEERING FN_A-сайт: v5r vs v5q) — сделана
      (L0-цикл, docs/250-re/100-formats/065-fw-trace.md); для late-point (б) карта уже на v5r.
- [x] **S4** — payload чтения iRISC-памяти → host-CR (мульти-слот +
      цикл). Mailbox-канал (КБ/команду) пока НЕ закрыт live — см. блок
      S2b/S2b-2 выше (вердикт (iii) + «не сел», DMA не выполнялась);
      до закрытия — чтение через CR-канал (v5l-класс). Маршруты
      закрытия — Фазы IX–XII. Закрыто R-C3 — H1b unconditional echo
      («Закрывает цель S4 на mailbox-канале», см. блок R-C3 ниже).
- [ ] **S5** — персистентность (FNP flash vs RAM на-бут) + recovery

## Фаза III — тулинг — [~]

- [x] **Перенос research-скриптов из /tmp в репо** (2026-09-23):
      `scripts/irisc/` (RE-тулинг + `iRISC.slaspec` пин 4c488a4) и
      `scripts/s1/` (S1 build-пайплайн) + README в каждой. Оригиналы в
      /tmp не тронуты (живая S1-сессия).
- [x] **dis.py bugfix'ы** (2026-09-23): канонический декодер —
      `scripts/irisc/irisc_dis.py` + golden-тесты `tests/test_irisc_dis.py`
      (Ghidra-пары): таргеты веток `PC+o*4` (был off-by-4); составные
      знаковые масштабированные офсеты ld/st (были сырые беззнаковые);
      порядок операндов st.* как в Ghidra (value,base). Заодно выяснено:
      slaspec STOREOFF15 (`hi<<10`) похоже баг синдиката — верно `hi<<11`
      (golden st.w 0x6ee02007 → 0x6).
- [ ] Унификация декодеров: канон — `scripts/irisc/irisc_dis.py`;
      `dec2.py`/`snips.py` — референсы; подключить s1-скрипты к канону.
- [x] **irisc-asm** — ЗАКРЫТО (2026-10-15, ветка `irisc-asm`, коммиты
      `6bd820d..251990e`; спека `docs/superpowers/specs/2026-10-15-irisc-asm-
      design.md`, план `docs/superpowers/plans/2026-10-15-irisc-asm.md`):
      ядро `scripts/irisc/irisc_asm.py` (канон-слой dis-синтаксиса + сахар +
      синдикат-диалект, decode-verify каждого слова, CLI вендор-совместимый
      + roundtrip/disasm/profile), профили cx5/cx4lx (strict-гейт, census),
      clcrc-API `mlxfwutil.clcrc_unwrap/clcrc_wrap`, кросс-декодер-гейт
      `make irisc-crosscheck` (Ghidra×irisc_dis, таксономия; 4030 и 1900-GCA
      — decoder_bug=0, unclassified=0), скилл `skills/irisc-asm/`; README
      `scripts/irisc/README.md` (lossy-реестр рендеров, таблица мнемоник).
      Известное ограничение: профиль cx6 отложен (владелец, до появления
      CX-6-потребителя).
- [ ] Ghidra-контейнер (план `2026-09-16-ghidra-irisc-containerfile.md`) —
      поддерживать в актуальном состоянии под I1/I2; 2026-10-25
      (canon-sync): печёт канон-сласпек в образ (spot-verify
      and.hi/bclr.1), crosscheck both PASS.
- [x] Фаззинг-харнесс (I3): генератор тест-векторов + CR-ридер (VSEC) +
      ledger результатов per-op (чтобы не терять прогресс между boot'ами).
      Закрыто I4 (fuzz-4, 2026-10-25): fuzzvec-режим `crates/mlxscope`
      (VSEC-посев + двухканальный verify out_mb/CR, быстрый цикл без
      reflash), вектор-артефакты `scripts/probes/cx5-fuzz4/` — см. Фазу I.

## Фаза IV — применения (ссылочно, вне прямого скоупа)

- Кабельный гейт «Cable speed not enabled» (docs/250-re/130-cable-gate/, TODO «Трансиверы»):
  полный decode MAIN_CODE → точечный патч таблиц вместо shellcode-обхода.
- Произвольный инспект iRISC-памяти (S4) → ROM-дамп/даталок-вопросы
  (TODO, docs/850-howto/130-rom-dump).

## Фаза V — порт детура на CX-4 Lx — [x] (2026-10-11)

**Итог фазы:** шаблон детура перенесён на CX-4 Lx полностью, L0–L4 закрыты;
3 образа (v1/v2/v3) легли чистыми при 5 burn-попытках (re-burn v2 в
эксперименте L3-B.2 и v3-попытка до ребута → erase-fail — урок «ребут между
burn'ами со сменой активации», строка L3). Девиация от §6 спеки: fresh ri
снимался перед v1/v2, но не перед re-burn B.2 и v3 — откатное покрытие
сохранено (ri-пара + build-образы + дуал-банк). Карта
bazzite 04:00.0 — на **detour-v3** (boot-детур + runtime-хук icmd + emit
маркера; CR-маркер 0xbadc0001 читается) — решение владельца «оставить
детур-образ». Прикладной уровень (детур-дамп памяти; sfp28 root-fix ~6 слов —
готовый рецепт: H0-хук + emit7) — следующий цикл.

Спека: `docs/superpowers/specs/2026-10-11-cx4lx-detour-design.md` (цели,
критерии C-L0..C-L4, дисциплина переноса поколений: **факт CX-5 на 14.32 =
гипотеза до верификации, в обе стороны**). Карта: bazzite `04:00.0`
(MCX4131A, 14.32.1900 GCA `MT_2430110032`); база — refs-сток 1900-GCA
(md5 `3bd3230b…`) + детур + guides; финал — детур-образ остаётся.
Организация A: план-файла нет, итерация лестницы = мини-план (бриф → журнал →
отчёт `docs/superpowers/reports/cx4lx-detour-lN.md` → строка сюда).
Worktree: `.worktrees/cx4lx-detour` (симлинки refs/build — **абсолютные**,
для контейнеров). Процессные правила цикла (владелец 2026-10-11): скиллы
`mellanox-flash-ops` / `mellanox-fw-build` / `ipmi-ops` — обязательны агентам
и координатору; знаниям MLNX_OFED не доверять; завис/дичь агента → перед
ретраем независимый аудит его сессии (скилл `analyzing-opencode-logs`);
burns/ребуты bazzite — без ограничений. Прикладной потребитель (после основных
исследований, не драйвер): детур-дамп памяти карты хостом (пример — root-fix
sfp28-ib-node: слова `0x0D600C..0x0D6012`, гейты `0xE2B4/0xD5DC`, ~6 итераций
× ~5 слов).

- [x] **L0. ISA-сверка 14.32** (2026-10-11, отчёт `docs/superpowers/reports/
      cx4lx-detour-l0.md`, журнал `…-l0-task-01.md`): гипотеза единой
      mlx5-кодовой базы **поддерживается** — unknown в коде 1.33%/1.09%
      (strict) vs 4030 1.28%/1.05%; ядро то же (0x36/0x0d/0x33/0x34, частоты
      ×0.98–1.12); **новых real op нет** (10 mask-op'ов = strict=0, табличный
      хвост); SHA-256 K-таблица-якорь @dc 0x319850 (64/64); редкие 4030-ops
      (0x16/0x38/0x1d) на 14.32 ≈0 — версионный хвост. Golden round-trip
      11/11 (set2/set3/st.d/jump/call + live-прецеденты). Бонус L1: entry
      dc=0x7edc, паттерн `call; st.d!; call 0x7ef0; self-jump` — той же
      формы, что 4030.
- [x] **L1. Геометрия детура** (2026-10-11, отчёт `docs/superpowers/reports/
      cx4lx-detour-l1.md`): точка **dc 0x7ee4** (raw 0x1756d0,
      `94000003→940c532f` call 0x31cba0; self-jump ×2 = dead — дельта: на
      CX-5 один); cave **0x31cba0..0x31cc00** (24 сл, 0x60B — **дельта:
      all-zero ≥256B на 14.32 нет**, макс 24 сл; 0 xref/access; вне db0);
      CR-слот **0x23f0/0x8fc — точный CX-5-аналог** (unlock-читалка
      @0xd4c8c + badc0ffe-compare, 36 call-сайтов, FW-записей 0; запасные
      0x23f8/0x23ec); scratch r5/r6 подтверждён (live-in только r1/r23 —
      дельта: r3/r4 на 14.32 write-first). **Эратата (L4): 0x23ec занят**
      (extm-mailbox addr, читатель ld.d @0xd497c — мимо ld.i-скана L1);
      свободный запасной один — 0x23f8.
- [x] **L2. Детур-v1 live PoC** (2026-10-11, отчёт `docs/superpowers/reports/
      cx4lx-detour-l2.md`): **C-L2 — с первого burn'а**: маркер
      **0xbadc0001 прочитан с хоста 4×/4×** (CR 0x23f0 через VSEC,
      cap 0x09; дискриминация: 0x223f0=0x88fc unmapped-дефолт, 0x23f8/
      0x23ec = бейслайны, COUNTER жив); карта здорова ([0207] IB, dmesg
      0 assert); банк B = detour-v1 (активен, байт-в-байт = сборке, md5
      `e91cac9c…`), банк A = L2' не тронут; откат
      `/root/bazzite-04_00-pre-detour-ri.bin`. VPI+guides включены (карта
      в IB-классе, как до цикла). Образцы: build_detour_v1.py
      (гейты [1]-[13], verify --deep/bootable/diff PASS).
- [x] **L3. iTrace-метки из шеллкода** (2026-10-11, отчёт `docs/superpowers/
      reports/cx4lx-detour-l3.md`): **событие от детура в ftrace поймано**
      (строка-маркер `memory_profile = 0xbad`, маска ICMD, арифметика 1:1
      к маркерам; mask 0 → тишина). RE trace-машины 14.32: **GATE 0x5f90**
      (r4=class, r5=level; mask=RAM w2, level=w3, L≥2 bypass),
      emit-обёртки 0x603c/6064/6090/6008 (r4=rt-строка, парамы r5..r8),
      **CORE 0x6124** (кадр 8 слов; класс/уровень в запись не входят).
      Схема v3: boot-emit исключён (H-early: ринг аллоцирует драйвер после
      FW-boot — вердикт в отчёте) → **runtime-хук icmd_generic_reg_access**
      (dc 0xd3850 → стаб 8 сл в кейве: stock emit первым + свой emit
      мёртвой db0-строки rt 0x00ada612). Банк A = v3 (активен, CR-маркер
      жив), банк B = v2. Уроки: badc0ffe-читалка не исполняется хост-путями
      (534K событий, 0 наших); между burn'ами со сменой активации — ребут
      (иначе erase fail). cargo 68 PASS.
- [x] **L4. Задел on-demand** (2026-10-11, отчёт `docs/superpowers/reports/
      cx4lx-detour-l4.md`): cmd-dispatch карта 14.32 — дверь fn 0xd4d58
      (CR 0x23fc, вход из ROM/iron), whitelist 0xd4714 (0x9001 разрешён),
      диспетчер таблиц 0xd4a24 (jump-таблицы @0x3147c0/0x3147d8), рег-доступ
      0xd3804 (L3-хук 0xd3850 внутри), **кадр = CR-окно 0x2014..0x2310**
      (инлайн, не стек — дельта vs 4030), extm-mailbox 0xd4948, cmdif_driver
      0x9464c. Кандидаты: H0 0xd3850 (live-доказан), H2 0xd4df4 (все
      разрешённые команды), H6 AN-FSM (~0.4 c «вечный читатель», условен).
      Read-канал: **рекомендован emit7 0x63bc — 7 слов/событие live**
      (sfp28-root-fix-дамп ~6 слов — одним событием; emit6/7 клобберят
      r10/r11); fallback CR 0x23f8 + резерв 0x2314..0x23e4 (35 сл, требует
      live-дискриминации). **Коррекция L1: CR 0x23ec занят** (extm-mailbox).
      Дельты шаблона vs CX-5: self-jump ×2, кейв 24 сл, r3/r4 write-first,
      читалка вне хост-пути, кадр в окне (не стек), exec-from-окна —
      гипотеза (безопасно через копию окно→кейв).

Гейты фазы: plan-review (спека + эта фаза) до L0; final-review на закрытии.

## Фаза VI — прикладной dump-полуфабрикат — [x] (2026-10-11)

**Итог фазы:** полуфабрикат готов и передан в handoff (D2b): параметризованный
build + два образа под их сток-ri `dacbcf0e` (MAIN_CODE ACA↔GCA
**байт-идентичен** — офсеты 1:1) с .ini build-ID (скилл R1/R2, трим без
force): **h0** `34e3c615…` (H0-хук, доказан v3/D1) и **h6** `ab5c1c81…`
(AN-FSM-автоном, live не валидирован — fallback h0). Строка-маркер
rt `0x00aeb83b` (**7×%x** — все слова видимы одним событием), r5=w2
self-check. Наша карта: откатана на detour-v3 (фаза V), D1-образ в банке B.

- [x] **D1. Dry-run на нашей карте** (2026-10-11, отчёт `docs/superpowers/
      reports/cx4lx-detour-d1.md`): **w2 == маска 1019/1019** (100%;
      1:1 к gated register-командам, пары stock→наш смежны по тикам) —
      «ld.d читает реальное слово и доезжает» доказано. Карта откатана на
      v3 (маркер CR ×2 подтверждён), банк B = D1-образ (md5 `efee4c67…`).
      **Урок D2**: форматная строка рендерит только парамы под свои `%x`
      (rt 0x00ada612 — один `%x`) → строка-маркер для потребителя — с
      числом `%x` ≥ видимых слов (скан db0) или сплит на группы. Ловушка:
      маркеры только `mstreg --reg_name MTRC_CAP -g`. Ядро полуфабриката:
      `build_dump_d1.py` (параметризован).
- [x] **D2. Полуфабрикат + handoff** (отчёт `…-d2.md` §5 handoff; D2b
      build-ID): строка 7×%x rt 0x00aeb83b; их base прошёл все гейты
      (байт-идентичность MAIN_CODE 3263488 B; DEV_INFO на месте — guides
      не нужен); образы h0/h6 + `build_dump_d2.py` + `scan_dead_strings.py`
      + README-dump; само-опознание `mstflint dc | head`.

## Фаза VII — boot-trace окно — [x] (2026-10-11)

**Итог фазы:** окно наблюдения бута доказано с двух сторон. **V1-lite**
(driverless, свой ринг): `mlxscope trace` — арм 0.39–0.51 с от
доступности устройства, события байт-в-байт драйверным, окно от FW t0
**9–15 с → ~2.0 с**; формат ринга отреверсен. **V2 (boot-окно, C-B2):**
boot-стаб C1 @0x7ee4 пишет boot-слова в CR-резерв — хост читает их
VSEC-поллом #0 (первая хост-команда после power-on); негатив-контроль
чист, селективность доказана. Побочно закрыта развилка main-init
(w0x2ef=0 → ветвь 0x7f94). Эраты: C2 не исполняется (wait-loop),
0x23f8 занят, резерв = 53 сл. Канон — docs/250-re/120-irisc/045-cx4lx-boot-window-cablepath.md.

Спека: `docs/superpowers/specs/2026-10-11-cx4lx-boottrace-design.md`.
Вопрос владельца: «кто запрещает наш код в FW при буте?» — никто; docs/250-re/120-irisc/045-cx4lx-boot-window-cablepath.md
фиксирует ограничение сток-конвейера (ринг в host-RAM ставит хост; маска
w2 при буте = 0). Две атаки: **V1** host pre-arm (свой ринг мимо mlx5 +
mstfwreset, судьба конфига readback'ом) и **V2** FW-side boot-log (хук
бут-сайта → st.d в CR-резерв 0x2314..0x23e4 = 35 сл, выгрузка VSEC до
первой хост-команды). Владелец: V2-буфер = CR-резерв 35 сл; обе фазы
(VII → VIII).

- [x] **B0. Recon (офлайн)** (2026-10-11, отчёт `docs/superpowers/
      reports/cx4lx-detour-b0.md`): протокол трейсера из исходников
      mstflint: mstfwtrace ставит ТОЛЬКО маску (ICMD SET_ITRACE 0xf003
      {unit_mask u32, log_level u8, log_delay u16}); ринг — MTRC-реги
      0x9040 CAP / 0x9041 CONF (mode+log_size+trace_mkey) / 0x9043 CTRL
      (arm), буфер через MTT-mkey; userspace-прецедент без драйвера —
      mtrcdump (VFIO, синдикат). mstfwreset: MFRL уровни 0/1/3(дефолт,
      bridge Link Disable)/4; FW перезапускается → конфиг трейсера
      гипотетически слетает (B1 readback). Сайты V2: рекомендована пара
      **C1 @0x7ee4** (live-proven, live-in r1/r23) + **C2 @0x8040**
      (финальный безусловный main-init call, live-in {r1}); конфиг-
      развилка по ROM-слову w0x2ef (путь 0xefc ⇔ цепь 0x7f94);
      emit-сайтов L≥2 в бут-дереве НЕТ (замаскированные при w2=0 не
      исполняются — класс закрыт негативом). Резерв CR 0x2314..0x23e4 —
      0 сток-обращений; 0x23f8 чист (boot-ready флаг).
- [x] **B1. Live V1 (без смены образа)** (2026-10-11, отчёт
      `docs/superpowers/reports/cx4lx-detour-b1.md`): **C-B1 достигнут**.
      mstfwreset L3: ресет 16.4 с (driver stop 8.0 / PCI+IRON 1.5 /
      driver start 6.6); FW перезапущен (MGIR 5998→343 c);
      **маска SET_ITRACE слетает** (и при unbind/rebind БЕЗ рестарта
      FW — сверх гипотезы B0); ринг перевыделяет mlx5 при probe
      (CONF/CTRL exclusive-quirk Lx подтверждён, 0x6C64FE/0xB63790);
      «ринг не у mstfwtrace» доказан live (без драйвера событий 0);
      потерянное окно **9–15 с** (probe 6.6 — жёсткий пол) → full-V1
      на драйвере бессмыслен. Превью B2: **VSEC работает в
      driverless-окне** — маркер v3 0xbadc0001 прочитан со свежего
      пост-ресетного бута. Полюс w0x2ef НЕ определён (баннер
      boot-only, замаскирован; rt = 0x00ADDB35, поправка к B0) —
      неважно: пара C1+C2 полюс-независима, C4 закрыт.
- [x] **B1b. V1-lite: driverless ранний арм своим тулом** (2026-10-11,
      отчёт `docs/superpowers/reports/cx4lx-detour-b1b.md`): субкоманда
      `mlxscope trace` (arm/drain/status; порт mtrcdump-флоу:
      AllocPD → CreateMKey-MTT → MTRC CAP/CONF/CTRL → SET_ITRACE
      0xf003). Live: driverless арм за **0.39–0.51 с** от доступности
      устройства, ownership без quirk; события в собственный VFIO-ринг,
      декод байт-в-байт драйверному, self-check PASS. Окно V1:
      **9–15 с → ~2.0 с** от FW t0 (ринг через 0.66 с vs probe 6.6 с);
      первые ~2 с бута остаются за V2. Бонус-RE: формат ринга
      отреверсен по живому дампову — записи 8B BE [hdr][data], типы
      0xa2/0xa3/0xff (timestamp), tdsn/tmsn; CORE-кадр docs/250-re/120-irisc/035-cx4lx-trace.md
      побит на записи (fixtures из живого дампа). Хост: IOMMU-karg
      включался на эксперименты и откачен в финале (+ ребут, cmdline
      чист). Гейты: 873 + cargo 95 (52 mlxscope). Коммиты d8e3405,
      5deb257, 47820a4.
- [x] **B2. Build + live V2** (2026-10-11, отчёт
      `docs/superpowers/reports/cx4lx-detour-b2.md`): **C-B2 достигнут**
      (сайт C1): boot-слова в полле #0 — первая хост-команда после
      power-on (mlx5-блэклист при активационном ребуте; репликация
      бут #2 POLL@19.95 c). Поймано: csr0x70@entry 0x00b1cba8 (3 бута
      бит-в-бит, сток 0), w0x2ef=0 (развилка → 0x7f94, закрыт вопрос
      B1), boot-ready 0xffffb00d, маркер 0xffffbadc. Негатив-контроль
      PASS (v3: резерв 0, v3-стаб тронул только 0x23f0).
      **Эраты:** C2 @0x8040 НЕ исполняется (wait-loop 0x8024 паркует,
      3 бута); 0x23f8 занят runtime; резерв 0x35 hex = 53 сл.
      Build: `build_bootlog_b2.py` (все D2-гейты, .ini build-ID,
      детерминизм, md5 `ca2d7a2d…`). Карта: банк A = v3 (нетронут),
      банк B = B2 (активен; откат ri `d75f601a…` готов).
- [x] **B3. Закрытие:** roadmap [x], docs/250-re/120-irisc/045-cx4lx-boot-window-cablepath.md (boot-окно +
      driverless-трейс + эраты), гейты, final-review.

## Фаза VIII — cable-path (QSFP/SFP-ветка + QDR/FDR) — [x] (закрыта 2026-10-15: T0–T2 done, T3 skipped, T4 done; final-review APPROVE)

Спека: `docs/superpowers/specs/2026-10-12-cx4lx-cablepath-design.md`
(написана 2026-10-12 по директиве владельца — БЕЗ запуска исполнения).
Железо подтверждено: QDR+FDR DAC, партнёр. MAIN_CODE один на семейство
→ SFP-ветка в нашем образе (исполняемость на QSFP-плате — T0/T1);
AN-FSM fn 0x1bdfa0 / сайт H6 0x1b9da4 (частота [H] до T1); строки —
driverless-трейс (VII), слова — хуки. Питает root-fix потребителя
(cx4lx-sfp28-ib-node — сейчас строят сами через vendored
dump_d2_core.py, T3 опционален); база T2 — свежий сток + только хуки
VIII; якорь v3 — офлайн (банк B активен: первый burn пойдёт в A —
план банков в спеке §0).

- [x] **T0. Recon (офлайн):** строки/маски кабельно-модульных и
      AN-событий; сайты ветвления QSFP↔SFP (I2C/SFF → решение) и
      слова скорости/состояния у AN-FSM; вердикт по SFP-ветке на
      QSFP-плате; кандидаты хуков. C-T0. — Готово (2026-10-14,
      `975a102`, отчёт `cx4lx-detour-t0.md`): ветвление по identifier
      МОДУЛЯ (byte0 `0x942c+0x70·m`; is_sfp fn 0x222670, QSFP28=0x11
      ∉ SFP-множеству → ветка не исполняется); маски T1 (core
      0x4404c60, AN 0x40, MM 0x400000, PMAOS 0x4000000, SMP 0x4000,
      phy 0x400, PLL 0x800, PTYS 0x20); хуки H-AN @0x1b9da4 (9 сл) +
      H-DEC @0x233094 (11 сл) = 20 ≤ 24.
- [x] **T1. Live baseline (без смены образа):** driverless-трейс
      линкапа QDR и FDR (DAC, партнёр; процедура — согласовать с
      владельцем); дифф строк/классов. C-T1. — Готово (2026-10-14,
      `527c046`..`01e0eb3`, отчёт `cx4lx-detour-t1.md`): QDR (AOC→свитч)
      LinkUp за ~15 с, agreed_ts3 speed=0x7 в трейсе, AN-раунд 302 мс;
      FDR DAC — вечный Polling с ОБЕИМИ партнёрами (CX-5 direct,
      InfiniScale-IV; дискриминатор B3 `3677bdd`/`7ded411`): биты
      0xf в Enabled, но chosen_mask→0x1 (SDR), verifier reject ~90%
      диспетчера, cnf_test недостижим; Enabled-маска модульно-зависима
      (AOC 0x07 ↔ DAC 0x1f) — ограничение в cable/PHY-пути. Гипотеза
      владельца FDR10-on-IB вне спеки [H] + Eth-факультатив — отчёт §7.
- [x] **T2. Build + live:** `build_cable_t2.py` (хуки branch/AN-FSM,
      emit7, бюджет cave ≤24 сл), гейты D2-класса + .ini build-ID,
      rb-фиксация + burn по банковому плану спеки §0 (дефолт: первый
      burn → банк A, якорь v3 офлайн; альтернатива v3→A-предburn —
      выбор владельца в брифе T2), линкап-дифф FW-слов. C-T2. — Готово
      (2026-10-14/15, `f1bd51c`..`698c1c8`, отчёт `cx4lx-detour-t2.md`):
      burn an5 (md5 2e86…, банк A) — H-AN emit5 жив, дифф QDR/FDR по
      FW-словам закрыт (retry = ctx-константы ↔ успех = динамика;
      0xf↔0x7, cnf_test 0↔×91, is_peer_legacy 0→1; chosen_mask=0x1 —
      НЕ маркер отказа); Eth-bonus T2d (шторм ~360 evt/s без партнёра,
      сток-подписи детекта ×3 модуля, линки 40G/50GbE 2x) + T2c-ревизия:
      H-DEC-сайт = state-8 хвост полного MM-прохода (только boot-init),
      re-hook не нужен (кандидат C1 @0x231a64). Отклонения: emit7→emit5
      (кейв 24 сл), rb-фиксация → no-fw-backup (якорь офлайн-образы).
- [x] **T3 (опц.). Semi-fabricate потребителя:** если их цикл ждёт —
      D2-паттерн под их сток-ri (хук SFP-ветки). C-T3. — Пропущен
      решением владельца (потребитель строит сам); запроса не было.
- [x] **T4. Закрытие:** roadmap [x], docs/250-re/120-irisc/045-cx4lx-boot-window-cablepath.md (без нового номера),
      гейты, final-review. — Готово (2026-10-15): §11 внесён
      (`3602b2e`); гейты: `make test-parallel` = 873 passed, cargo =
      95 passed (26+17+52, 2026-10-15); final-review (Kimi K3) =
      **APPROVE**, 4 минора погашены этим же коммитом (указатели t0
      /tmp→scripts, кросс-ссылка T2d→T2c, метки тёплый/холодный в
      §11, гейты в roadmap). Фаза VIII закрыта.

## Фазы IX–XII — каналы возврата результата (readback) — [ ]

Стартовая точка: отчёт
`docs/superpowers/reports/irisc-exec-and-readback-analysis.md`
(инвентаризация методов, три ошибки рассуждений, маршруты R-A..R-D,
контекст цели secure_fw). Итог анализа: исполнение воспроизведено
полностью (S2 v5l CX-5; H0 CX-4 Lx); провалена только доставка своих байт
в host-память на CX-5 — у синдиката ответ едет **штатным completion**,
самодельный DMA (X1/ICM) — тупик (доказано S2b2/S3). Порядок (владелец
2026-10-15): максимум на CX-4 Lx → далее CX-5-маршруты; треки IX
(bazzite 04:00.0) и X–XII (81:00.0) независимы по железу. Все фазы —
non-secure прошивки (см. шапку).

## Фаза IX — CX-4 Lx: полный dump-цикл (R-A) — [x] (2026-10-16; итерация 2 R-A4b исполнена 2026-10-17 — отрицательный результат, см. ниже; критерий фазы закрыт итерацией 1)

Цель: функциональный аналог `dump-memory` синдиката на Lx — чтение
произвольных RAM-адресов по требованию хоста; транспорт = CR-окно/emit
(mailbox-DMA не нужен). Все компоненты live-доказаны по отдельности
(H0-хук L3, ld.d→emit D1, окно-инлайн L4, boot-log B2) — фаза собирает
их в цикл. Потребители: детур-дамп (D2-класс), будущий инспект для
secure_fw-арки. Спека:
`docs/superpowers/specs/2026-10-16-cx4lx-dumpcycle-design.md` (владелец
OK 2026-10-16: стейджинг параметризованный стаб → опц. generic exec;
канал B/C по факту R-A2; финал — dump-образ остаётся активным; состав —
VPI 0x07 + 56G/100G-биты, 0x3b→0xfb).

- [x] **R-A1. Бюджет кейва** — Готово (2026-10-16, отчёт
      `docs/superpowers/reports/cx4lx-dumpcycle-ra1.md`, журнал `…-ra1-
      task-01.md`): C-канон **20/24 сл** (slack 4; self-consume 21) —
      один кейв; B в один кейв live-формой не влезает (set-pair 25 /
      base-zero 23 slack 1<2) → **B-сплит 0x31cb70 (9+мост)+кейв =
      26/34** (slack 8); запас emit5×2 (21/24); итерация 2: copy-loop
      стаб 22/24, пейлоад-буфер ≤10 сл (фрагмент 0x31cb70); **второго
      кейва нет** (db0-дыры — живые данные); cmp-фильтр на 14.32 —
      op0x36-идиома (86 cc0a-свидетелей), op38 ≈0 сайтов.
- [x] **R-A2. mapped-дискриминация CR-резерва 0x2314..0x23e4 (53 сл)**
      — Готово (2026-10-16, отчёт `…-ra2.md`, журнал; live без burn,
      карта на an5 не тронута): **53/53 mapped** (стабильны ×3 свипа) →
      **B первичен**; прямой VSEC-write в окно работает (raw-посев +
      host-clear, 0 доп-слотов стаба); **инлайн-зона волатильна**
      (reg-трафик сбрасывает посев), резерв держит → magic/addr/N только
      в резерве (скетч спеки «посев 0x805+k» live опровергнут); 0x23f8
      занят runtime (эрата B2 на an5); контроли чистые (0x223f0=0x88fc).
      Аномалия: хост bazzite найден выключенным — поднят BMC power-on
      (журнал §2).
- [x] **R-A3. Runtime-хук + посадка payload** — Готово (2026-10-16, план
      `docs/superpowers/plans/2026-10-16-cx4lx-dumpcycle-ra34.md`, отчёты
      `…-ra{3,4}.md`): H0-эталон @dc 0xd3850 → параметризованный стаб
      (C-канон 20/24; B-сплит 26/34), посев хостом в резерв 0x8c5/0x8c6
      (инлайн-волатильность R-A2 учтена), magic-фильтр cmp **op0x38 eq32
      доказан live** (негатив 163.8 с / позитив K-константы; op36-запас не
      нужен), `mlxscope dump` + `build_dump_ra3.py` (20 гейтов, оба
      канала); два burn `--no_fw_ctrl` (банк B → ra3c, банк A → ra3b),
      карта жива (asserts=0, identity инвариантна), идемпотентно.
- [x] **R-A4. Readback-канал** — Готово (оба канала; **критерий фазы
      закрыт**): ≥6 слов произвольного RAM-адреса за один триггер без
      reflash — C = emit7 rt 0x00aeb83b (7 парамов), B = резерв CR 0x2320
      (READY=magic-эхо + d0..d5, poll за 1 попытку); 3 ground-truth класса
      бит-экзакт (ro-data/код/RAM), image-ld.d дискриминатор = SHA-256
      K[0..5], негатив чист. **Режим-факт: окно хендлера живо только под
      armed SET_ITRACE** (эрата docs/250-re/120-irisc/050-cx4lx-dump-cycle.md — обязательно потребителям);
      финал = ra3b активен, PTYS 56G/100G в runtime-стемпинге (ethtool).
- [x] **R-A4b. Итерация 2 — generic exec** — исполнено (2026-10-17,
      аддендум плана `…-ra34.md`, отчёт `…-ra4b.md`; **отрицательный
      результат — критерий не закрыт**, исход ниже). **Исход:** тулинг
      закрыт (`mlxscope dump exec` — посев ≤10 сл + readback-verify до
      триггера; билдер `--chan g` + `ra4b_payloads.py`, оба `--copydone`;
      cx4lx-профиль +3 live-формы cmp38_eq32/or/csr.w, base-zero st.d
      остаётся 'assumed' — P4 не выполнялся); live: burn/активация/
      rb-целостность/негатив-E0 чисты, но **любой armed-триггер через хук
      клинит CMDIF** (rc=124, 4 wedge / 4 загрузки; BMC-рековери полный;
      unarmed-потоки чисты 12.4–12.8 мс). Бисект (off-ребёрн, рулинг
      координатора): tail-shift/маркер исключён → **класс head/armed**
      (тело пещеры после cmp + armed-окно, либо armed-механика с
      хук-сайтом; на миссе тело не исполняется — статическое противоречие;
      механизм FW не установлен). P1–P3 не выполнялись, P4/marker N/A.
      Банки (факт): burn пишет НЕактивный банк → **A = ra4b-off (активен),
      B = ra4b-on**; ra3b перезаписан, бит-воспроизводим билдером (md5
      `3fccc48c…`). Владелец 2026-10-17: зафиксировать, не копать; банки
      не трогать, ra3b не возвращать; переход к CX-5 (фаза X) отложен.
      Канон деталей — docs/250-re/120-irisc/050-cx4lx-dump-cycle.md (подсекция итерации 2). **Почему
      возникло:** решение владельца 2026-10-16 на этапе спеки — стейджинг,
      чтобы не блокировать критерий фазы (C-RA4 закрывается итерацией 1);
      заделы сняты R-A1 §2 (copy-loop стаб 22/24, пейлоад-буфер ≤10 сл во
      фрагменте 0x31cb70). **Почему доделать:** (1) итерация 1 даёт только
      фиксированный стаб с параметрами — exec произвольного кода хоста без
      reflash (S2-аналог) остался последним недостроенным компонентом
      аналога инструментария синдиката; (2) потребители упираются в этот
      примитив: инспект secure_fw-арки (главный), детур-даунгрейд
      D2-класса, переменный N / loop-стабы для длинных дампов; (3)
      себестоимость минимальна — всё дорогое уже доказано в фазе IX
      (H0-хук, окно + эрата armed, посев VSEC, exec-from-cave boot-детуром,
      геометрия), остаток = досборка листинга + гейты + burn + live-цикл
      (2–3 задачи SDD). *(Оценка (3) не подтвердилась: live-часть упёрлась
      в armed-wedge вне статического анализа.)* Критерий (формулировка
      по эрате (2) спеки): хост сеет ≤10 слов машинного кода → стаб
      копирует окно→**фрагмент 0x31cb70** → исполнение подтверждено
      наблюдаемым эффектом пейлоада (маркер в резерв / emit), без reflash
      между пейлоадами.

Гейты: спека + plan-review до R-A3; final-review на закрытии.

## Фаза X — CX-5: ICMD-дверь (R-B) — [x] (закрыта 2026-10-18: R-B1/R-B2
done, вердикт (а) окно-инлайн; исполнение SDD ветка cx5-icmd-door-rb
(merged в dev 6d0cf0d..4527925), final-review APPROVE; канон
`docs/superpowers/reports/cx5-icmd-door-rb1.md`. GO владельца
2026-10-18 — блокировка «отложено 2026-10-17» снята; спека
`docs/superpowers/specs/2026-10-18-cx5-icmd-door-design.md` + план
`docs/superpowers/plans/2026-10-18-cx5-icmd-door-rb.md`, plan-review
APPROVE (REVISE→фикс `2af1aca`→APPROVE). Live-дискриминация при вердикте
(в) — предодобрена, не потребовалась (вердикт (а)): оба хоста, карта по
Base GUID — реестр `CARD_CX5_EDR100` (81:00.0, v5r), без burn)

Цель: карта двери-слоя 4030 (аналог isr_icmd 0xd4d58 + рег-доступа
0xd3804 на 14.32; гид — карта L4: кодовая база контр-плейна похожа,
дельты — по факту) + вердикт: живёт ли кадр инлайн в host-видимом
CR-окне (тогда ответная нога без DMA вообще — перенос Lx-паттерна на
CX-5). S1/S2 картали только mailbox-слой (синдикат-путь); дверь на 4030
не картали.

- [x] **R-B1. Recon (офлайн)**: дверь (CR 0x23fc-аналог) / валидация /
      диспетчер / рег-доступ на MAIN_CODE 4030; где кадр (окно vs
      стек-копия — дельта vs 14.32); геометрия CR-окна. Критерий: карта
      + хук-кандидаты класса H0/H2 с критериями L4 §4.
      *(Done 2026-10-18: карта полная — дверь fn 0x1077f0/слот 0x8ff
      (слово bit0-valid/bit1-extm/hi16-opcode — lo16-гипотеза L4
      опровергнута), валидатор 0x1071a0 (0x9001 разрешён), диспетчер
      0x107488 (jump-таблицы rt-записи), REGACC 0x106350, окно
      0x2000..0x23fc (st.i=0; FW WB walking-base st.d!); хуки H0
      0x106390/H1 0x10788c/H2 0x1078a0. Канон:
      `docs/superpowers/reports/cx5-icmd-door-rb1.md`; хелпер-гейты
      G1–G10 ALL PASS.)*
- [x] **R-B2. Вердикт применимости**: кадр в окне → детур по
      S2/H0-образцу (спека/план отдельно); стек-копия → приоритет Фазы XI.
      *(Вердикт **(а) окно-инлайн** — кадр рег-команды читается из слов
      окна (ld.i + EA copy-loops), ответ пишется в окно (walking-base
      st.d!); Lx-паттерн переносим, ответная нога без DMA. Ветка (в) не
      наступила — live-дискриминация не потребовалась (Task 4 SKIP).
      Next: детур-спека по исходу (а).)*

## Фаза XI — CX-5: success-path детур (R-C, syndicate-literal) — [x] (2026-10-21, R-C3)

Цель: байтовый канал ответа на CX-5 через **штатный completion** (как у
синдиката): payload пишет в стейджинг, который тело/эпилог fn 0x0e4250
штатно переносит в out_mb (QUERY-серия 56 слов уже доезжает в наших
прогонах — S2b2 A.1). Ошибку S2b/S2b2 (самодельный DMA X1/ICM) не
повторять.

- [x] **R-C1. Проба CREATE+QUERY на 4030** (live, без burn, дёшево):
      сырой cmdq-POST из mlxscope; switchdev-режим драйвера не нужен
      (это политика драйвера; прецедент 16.19.1200 — docs/250-re/110-signing/030-root-of-trust.md).
      Критерий: status 0 по созданной таблице на 4030.
      *(ДОСТИГНУТ — `mlxscope flowtable` (Q→CREATE→Qcreated→DESTROY):
      Qcreated status=0/syndrome=0x0, контекст с log_size-отражением
      `04`@0x1b (ground-truth out-hex снят), негатив 3/0x1c2b78 той же
      сессией, идемпотентно ×2; карта на v4-echo, гигиена VFIO чистая.
      Канон `docs/superpowers/reports/cx5-successpath-rc12.md` §1;
      журнал `journal/2026-10-21-cx5-successpath-rc12-task-02.md`.)*
- [x] **R-C2. RE стейджинга→completion** (офлайн): из какого стейджинга
      тело (resume 0x8E4380+) и wrapper 0x18d8b0 строят out-слова; куда
      писать наши байты (целевые смещения).
      *(ЗАКРЫТ — success-стейджинг = [r1+0x58..0x98) (writer FN_A r10),
      сборник 0x0e4424 мержит staging→response (+0x18/+0x1c/+0x20/
      +0x30/+0x38), перенос = completion fnptr [ctx+0x140] (r8=0x40)
      через 0x90be4/m2; A.1 объяснена (56/56 слов серии — расширенный
      mailbox-чанкинг, вне 0x40-окна); hook-рекомендация R-C3: HC-1
      late-site 0x0E43C4 + QUERY-носитель 40B (v4-echo keep-echo, 23 сл,
      slack 2); потолок 56B/команду verbatim / 40B slack-compliant.
      Гейты G1–G8 ALL PASS (`scripts/probes/cx5-successpath/
      rc2_staging_map.py`, лог `build/cx5-successpath-rc2.log`).
      Канон `docs/superpowers/reports/cx5-successpath-rc12.md` §2–§6;
      NB: слово call @0x0E437C исполняется на каждом slow-path QUERY —
      success обходит ветку BadParam @0x0E4388, не сам сайт.)*
- [x] **R-C3. Детур + burn + live** (спека/план, owner GO): слова хоста
      в out_mb на предсказанном смещении, status/syndrome штатные,
      идемпотентно. Закрывает цель S4 на mailbox-канале (КБ/команду).
      *(ДОСТИГНУТ — H1b unconditional echo: стаб 23 сл в S0-кейве на базе
      v4-echo keep-echo, хук @0x0E43C4; burn `--no_fw_ctrl` с первой
      попытки, активация по build-ID R-C3 (dc byte-exact); echo-лестница
      P1/P2/P3 ×3 повтора byte-exact (out+0x10..0x38 == payload), канарейка
      `6f28` жива, негатив BadParam не достигает сайта; КБ-демо N=32
      (1280 B) losses=0, 16720.5 cmd/s / 668820.8 B/s. F1/F2/F3 не
      наступили. Канон `docs/superpowers/reports/cx5-successpath-rc3.md`;
      ledger `docs/superpowers/ledgers/cx5-successpath-rc3.progress.md`;
      карта остаётся на R-C3-образе (policy).)*

Гейты: спека + plan-review до R-C3; final-review на закрытии.

## Фаза XII — CX-5: C-lever / intake-регистрация (R-D) — [x] (закрыта 2026-10-21, success-with-amendment)

Цель: неарифметическая форма доставки: RE intake-регистрации буферов
команды (писатели entry+0xc, формат ключа C — follow-up S3-(а) + след
ICMC-miss 2026-10-09) → m2-вызов (0x18064c) с зарегистрированным ключом
**собственной** out_mb. Owner-gated (запись в реальный registered-буфер).
Побочно: декод ICM-транспорта — фундамент для secure_fw-арки.

- [x] **R-D1. RE intake** (офлайн): где парсятся mailbox-указатели
      командного блока; кто/когда пишет entry+0xc; формат C;
      FETCH/POST-пара для in_mb/out_mb нашей команды.
      *(Готово 2026-10-21, вердикт **(а)**: C = table_id|0xff — сток сам
      вычисляет [r1+0xac]|0xff в r8 прямо на хук-сайте; регистратор —
      CREATE (стейт-машина 0x0e2130), на QUERY-пути до хука писателей нет,
      де-рег — completion-кластер; entry 16B {+0 flags, +2.b бит1
      registered, +4 id, +8 v-FETCH, +0xc v-m2-lookup}; единая причина
      m2′-miss — v-страница реестровая ([entry+0xc] = FW-назначенный ICMC
      va), арифметика строила va из IOVA; побочно закрыто происхождение
      синдрома Q(0,0) 0x31c2b78 (F_SYN-валидация FETCH-мусора). Гейты
      G1–G10 ALL PASS — `scripts/probes/cx5-clever/rd1_intake_map.py`;
      аддендум П.1–П.6 к спеке — вход R-D2.)*
- [x] **R-D2. Вердикт + проба** (owner GO): C-ключ нашей out_mb →
      m2-POST → маркер в out_mb0. Успех — второй байтовый канал (дубль
      XI); провал — закрытый RE-вывод по транспорту.
      *(2026-10-21, **success-with-amendment**, ратифицирован владельцем:
      канал доставки доказан — m2-вызов 0x18064c с зарегистрированным
      C=table_id|0xff (стаб 16 сл @0x38d774, хук late-site 0x0E43C4,
      образ rd2-v9) доставляет FW→host 40B payload байт-в-байт ×3 в
      детерминированную зарегистрированную host-DMA страницу @0x10689000
      (BE-скан 256 MiB: ровно 2 адреса — staging + посадка); негатив
      0x1c2b78 golden ×3, идемпотентность ×3, карта жива (остаётся на v9).
      Класс задачи Фазы II решён неарифметически; произвольный адрес
      назначения невозможен — страница = FW-назначенный ICMC va. Поправка:
      readback-канал аддендума (@out_mb0+0x1b через follow-up FETCH-merge)
      опровергнут механически — POST затирает FETCH-валидируемые байты
      (пост-TRIG 0x66cbbb; риск предсказан спекой §4); readback-полировка —
      опц. фолоу-ап. Сага дефектов D1–D8+M1/M2: 9 образов v1–v9 + 3
      тул-патча (ff335fa..62c275d). Канон —
      `docs/superpowers/reports/cx5-clever-rd.md`; ledger
      `docs/superpowers/ledgers/cx5-clever-rd.progress.md`.)*

Гейты: спека + plan-review (Kimi K3, APPROVE_WITH_FIXES → фикс `13840b2`)
до старта; `make test-parallel` **1021 passed/1 skipped** + cargo test
workspace ok (**26+20+159 = 205 passed**) — по журналам цикла (финальный
закрывающий прогон + final-review Kimi K3 — координатор).

## Фаза R-E — CX-5 4030: дверной детур (dump-cycle через ICMD-дверь) — [x]

Цель: замкнутый dump-цикл на v5r 81:00.0 (посев в CR-резерв → mstreg
→ стаб H0 читает слово → ответ в резерв → VSEC), без DMA/reflash.
Спека/план/отчёт: `2026-10-19-cx5-door-detour*`; канон —
`docs/superpowers/reports/cx5-door-detour.md`.

- [x] **RE1–RE3.** Стаб-слова (decode-verify) + pre-flight (канал B,
      arm не нужен, посев держит) + builder Rule 1–4 + burn
      `--no_fw_ctrl` (канон, доктрина-фикс по инциденту MCC).
- [x] **RE4.** Батарея **5/5 GT-совпадений** (оба класса, без reflash,
      первый полл); негатив — amended-чтение (спека-поправка: addr-0-echo
      маркер, 0x8c6 стабилен при трафике); identity инвариантна.
      **Фильтр-матрица v1–v12: magic-зависимая обработка на H0 мертва
      всеми механизмами** (cmp38/cc0a ×6, subs/cc2, value-маска грязная/
      чистая) — открытый RE-факт; H1/H2-хук-сайты — неразведанное
      направление. Карта на v4-echo образе.
      RAM-читатель через дверь — рабочий инструмент: clear → seed
      addr → mstreg-триггер → read 0x8c8 = **слово RAM карты по
      засеянному адресу** (host шлёт только адрес, ответ — содержимое
      памяти; GT-доказано на ro-data). Фильтр для чтения не нужен.

## Фаза R-F — CX-5 4030: условный стаб (тихий без посева) — [x]

Цель: вернуть букву негатив-контроля C-RE4 («без посева — 0 наших
ответов»): условный стаб, молчащий без host-посева. Основание — матрица
v1–v12 (отчёт `cx5-door-detour.md` §3): на H0 условность мертва всеми
проверенными механизмами. Dump-capability закрыта (R-E echo-читатель) —
фаза про чистоту окна/stealth, не про чтение. Спека/план/отчёт:
`2026-10-23-cx5-cond-stub*`; канон — `docs/superpowers/reports/cx5-cond-stub.md`.

- [x] **RF1. H1/H2-разведка** (офлайн): оба сайта BUILDABLE (scratch
      {r5,r6,r7,r9–r11}+; r18/r19/r21/r22/r23 LIVE, r20 DEAD — уточнение
      rb1); hook-слова simm24 0xA17B1/0xA17AC decode-verify; дверной
      cc-инвентарь: cmp38/cc0a пар на door-пути — 0, subs-census 21.
- [x] **RF2. cc-source RE на H0** (офлайн): матрица v1–v12 закрыта
      класс-декомпозицией — cmp38/cc0a-канал мёртв на слоте H0
      операндо-независимо (не глобальная cc-смерть двери); v10 = неверный
      cc-selector (cc2 ≠ eq); v11/v12 = ALU-порядок sub-семейства
      (SUB_MODEL: subs = rt−rs — гипотеза-наследие, live-D2 опционален).
- [x] **RF3. Условный стаб + батарея** (owner burn): рулинг сайта H0
      (механизм → clobber → шум); w-a D1-проба — cc0-ветвление живо на
      слоте; **w-b лэндинг: C-RF3 PASS** — позитив 18/18 GT first-poll
      ×3 раунда (оба класса), строгий негатив 15/15 rc=0 (0x8c8..0x8cf
      нули, addr-0-эха нет), идемпотентность ×3; w-c (H2 data point,
      owner): идиома подтверждена на втором сайте двери (30/30+25/25),
      H2 — proven-фоллбек. Карта на w-b (runtime-верифицировано).
      Операционный урок (№43, уточнён при закрытии): ребут верифицировать
      uptime/boot-id — poll «host up» подключается и к неперезагруженному
      хосту (инцидент: команда ребута умерла на parse-error, хост не
      уходил); после каждого reload обязателен runtime word-gate на
      hook-сайтах (dc-build-ID/q флеш/рантайм не различают). Реальные
      ребуты дня перезагружали FW 4/4.

## Критерии готовности

| Фаза | Критерий |
|---|---|
| I | MAIN_CODE декодируется в Ghidra без decode-gaps; семантика ядра (0x36/0x0d/0x33/0x34) верифицирована фаззингом |
| II | C1–C4 спеки (on-demand exec + read, персистентность) |
| III | dis.py без известных багов; irisc-asm в репо; фаззинг-харнесс воспроизводим |
| IV | по мере появления задач-потребителей |
| IX–XII | байтовый readback: слова произвольного RAM-адреса хосту за один триггер без reflash (Lx — окно/emit; CX-5 — штатный completion / registered-POST) |
