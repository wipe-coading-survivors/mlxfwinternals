# s2/ — билдер S2-образа (on-demand iRISC, план 2026-09-24-irisc-ondemand-s2)

Статус: **S2 ЗАВЕРШЁН — FULL C1** (v5l live 2026-10-02; журнал task-34,
отчёт `docs/superpowers/reports/irisc-ondemand-s2.md`). Текущая версия —
**v5n** (mode "B", `build_s2.py OUT 19` — m2′ X1-from-p0, DIRECT POST,
s2b2: секция v5n ниже); **v5m** (mode "B", `OUT 18`) — первая S2B-версия
(output-mailbox WRITE-POST, task-02 s2b); v5l — финал S2.
Летопись разработки: Task 4 + task-07
GUID-fix + task-10 v4 +
task-16 v5a + task-18 v5b + task-20 v5cA + task-21 v5cB + task-23 v5d +
task-25 v5e + task-27 v5f + task-28 v5g + task-29 v5h + task-31 v5i +
task-32 v5j + task-33 v5k rev.2 + task-34 v5l.
Детур call-сайта handler'а QUERY_FLOW_TABLE + стаб (v5l: 14 слов,
третья C1-попытка — v5k МИНУС реплика, r3 = call-site resume
0x008E4380: p3 возвращает payload В ТЕЛО fn в точке возобновления
call-сайта (как вернул бы FN_A) → тело достраивает QUERY →
сток-completion; v5k rev.2: 24 слова,
вторая C1-попытка — exact-S2OK сборка (set3 rs=zero) + выход через
стороннюю ЭПИЛОГ-РЕПЛИКУ fn (10 слов byte-exact сток @0x0e42e8..0x0e430c
— ресторы r17-r23, поп 0xf8, внешний [R+4], финальный ret.r; пре-лоад
r3 абсолютным адресом реплики — базо-независимость by construction);
livelock rev.1 (внутренний [r1+4]=0x8E435C) и утечка r17-r23 устранены
by design; v5j: 12 слов
exec-from-input C1-попытка, rev.2 exit-C — НОЛЬ записей во фрейм,
no-link передача, payload 4 слова in-place из зоны посадки; v5i: 15 слов neutral-write; v5h: 22 слова
no-save linear; v5g: 23; v5f: 32; v5e: 30; v5d: 33 слова
stock-conformance копи-путь; v5cB: 34 слова full-write-path
инструментированный; v5cA: 21 слово frame-only; v5b: 33 слова
C1-attempt с фильтром и gauntlet; v5a: 9 слов echo-probe; v4: 33 слова;
v2: 34) в доказанной ID-зоне.

## Назначение

`build_s2.py OUT [VERSION]` собирает S2-образ из базы patched3: детур
call-сайта 0x0e437c handler'а QUERY_FLOW_TABLE (`call 0x38d750`) + стаб
в доказанной ID-зоне 0x38d750–0x38d7d8. Финальная схема (v5l, FULL C1):
magic-фильтр MAGIC16 @input[0x12] (слот [r1+0xaa]) → эхо CR 0x2380/0x2384
→ no-link передача `ret.r zero,r8,r11` на payload В input-зоне посадки
([r1+0xac], 4 слова) → S2OK → CR 0x2388=0x53324F4B → выход по call-site
resume 0x8E4380 в тело fn → штатный completion; кадры без MAGIC —
fast-path tail-jump FN_A (стоковые аргументы нетронуты). Исторические
версии (v1–v5k, включая исходный режим-A протокол «[0]=MAGIC S2CM,
копирование N слов на стек») — секции ниже; v1/v3 текущим билдером не
собираются (STUB_LAYOUT: версии 2, 4–17; v1 — до-selector-фикса R9,
v3 = v2+guides-пайплайн, superseded v4+).

## v2 (фикс selector, task-07-debug → plan-fix R9)

- v1 (md5 `4f354b6fb79ff0840c84e0da30eda041`, сожжён) вис на G-fallthrough:
  слово cmp38 @0x38d764 `e1806800` имело selector funct5=0 — кодирование
  вне всех 3734 FW-сравнений, не live-проверено → trap/stall командного CPU
  (journal task-07-debug §Вердикт T3).
- v2: funct5=2 (eq32, live-proven fuzz-2 P2 `e0a00002`), rt=r13 — FW-прецедентная
  форма (3/26 сайта): слово `e1806802`, enc.cmp38_sel(2, 12, 13).
- Дифф v1→v2: ровно одно 32-битное слово (de-CRC код-секции) @0x38d764
  `e1806800`→`e1806802` + clcrc линии 0x38d740 + ITOC CRC (сырые байты:
  1 байт слова, 2 байта clcrc, 4 байта ITOC).
- md5 v2: `d91d800b967cdeb786df4858d59d42b7`; verify --deep PASS,
  mstflint bootable PASS, rebuild детерминирован.

## v3 (task-07: bake GUID/MAC карты)

- Дефект (owner-flagged): все S1/S2-образы без baked GUID'ов — при burn с
  `--ignore_dev_data` карта GUID'ы НЕ сохраняет (docs/850-howto/100-cross-flash-ops §6): секции
  device-данных берутся из образа; live-симптом — zero-MAC netdev. Ретракция
  прежних утверждений «наследуются из базы» — журнал task-07-guids.
- v3 = v2 + вшитые GUID/MAC карты тем же механизмом, что `python3 mlxfwutil.py
  guides` (`bake_guids()` в build_s2.py: `MDevInfo.write_uids` +
  MFG_INFO uid/mac @0x28/0x38 + section/entry CRC; тесты доказывают
  байт-эквивалентность выходу CLI `guides` на v2).
- `CARD_GUID`/`CARD_MAC` — реестр `CARD_CX5_EDR100_GUID`/`_MAC` (`mlxfwutil.hw`); провенанс —
  стоковый бэкап `ri-s1-backup-20260922.bin` (md5
  `ff43673c2edafe974a551f216bd55`), MFG_INFO == DEV_INFO, OUI b8:59:9f
  (Mellanox).
- Дифф v2→v3: 34 байта, только GUID-секции — DEV_INFO (guid/mac/
  vsd_vendor_id 0x15B3 из `ensure_valid` + insection CRC), MFG_INFO
  (guid/mac), DTOC entry[5] CRC; ITOC 0x03 (MAIN_CODE со стабом)
  байт-в-байт как v2.
- md5 v3: `f7a91f14b3756092b1a9cd01376b51f4`; verify --deep PASS,
  mstflint verify bootable PASS, `mstflint -i <v3> q`: Base GUID/MAC =
  значения карты (не N/A).

## v4 (дискриминатор DISCRIM32; task-09/task-10, итерация C1-retry)

- Причина: R5 live-факт (T7 v2) — диспетчер маршрутизирует по input[0..2],
  MAGIC@0 умирает pre-handler (status 2/0x3590f5) ⇒ фильтр v2 недостижим.
  v4 фильтрует по **DISCRIM32 = 0x0432434D** @input[8..0xC) (T9: TT=0x04 —
  не-сток, но гейты TT проходят, live-доказанный класс; pad=0x32 — не-сток,
  FW до call-сайта не читает; tn=0x434D не читается).
- Раскладка input v4 (T9 §Step 9): `[0]=0x09320000 (опкод-слово, фикс),
  [4..8)=0 ОБЯЗАТЕЛЬНО (валидатор G5/G6/G7), [8]=DISCRIM32, [0xC]=N,
  [0x10]=r5, [0x14..0x14+4N)=код` (N≤4, окно 0x24). r6-слота нет.
- Стаб: 33 слова (v2 34 − r6-init; save/restore r6 сохранены — r6 остаётся
  site-значением даже при payload, пишущем r6); эхо 0x2380 ← сравненное
  слово (=DISCRIM32 на магии), 0x2384 ← N; cmp38_sel(2) eq32 — то же
  live-proven слово `0xE1806802`, что в v2; resume live-PC 0x00B8D7BC;
  W_FAST @0x38d7d0. Полная слово-таблица — журнал task-10.
- Маркер-лайт (T5): 4 слова `24075332 20e74f4b 6c043b8a fc001825`
  (S2OK=0x53324F4B → CR 0x2388; r5-эхо 0x238C снято по бюджету). Гейт G5'
  (T11) проверяет 0x2388=0x53324F4B.
- **Синдром-ожидание (T9 concern 2):** дискриминаторные прогоны завершаются
  status 3 / **0x66cbbb** (TT=4-класс), НЕ 0x1c2b78; fallthrough (сток-нули)
  → 0x1c2b78 как в v2. TRIG_CMD v4 hex — журнал task-10 §TRIG_CMD.
- Дифф v3→v4: DEV_INFO/MFG_INFO байт-в-бит v3 (GUID-пайплайн не тронут);
  de-CRC код — 17 слов, все в стаб-зоне 0x38d754–0x38d7d4; файл — только
  ITOC 0x03 raw (clcrc-линии + section CRC) + CRC ITOC-entry.
- md5 v4: `bfc0f0b0907c86e8458b2e0e11e27deb`; verify --deep PASS, mstflint
  verify bootable PASS, серверный `mstflint -i q` (file-query, без карты):
  Base GUID/MAC = значения карты; rebuild детерминирован.

## v5a (echo-probe; task-16, после T15-final «decode-доказанного слота нет»)

- Причина: T15-final (журнал task-15 §12-13 + errata) — хвост D-блока
  ([D+0x18..0x40)) размечается блоб-маршалом, писатели не трассированы;
  линейные модели (L/RAW) опровергнуты live. Слот v5-фильтра неизвестен
  ⇒ вместо фильтра — эмпирическая карта посадки: один burn + probe-матрица
  (T17) → решение v5b.
- Стаб: 9 слов, БЕЗ фильтра/фрейма/payload/csr_r: на КАЖДОМ приходе 0x0932
  в детур `ld.w r12,[r1+X]; st.d r12,0,CR_X` для
  X∈{0xa0 (контроль tn, посадка доказана), 0xaa, 0xac, 0xb2} →
  CR{0x2380, 0x2384, 0x2388, 0x238C}, затем `jump FN_A` (stock-style,
  слово 0x95F8007D @0x38d770). Clobber только r12; ra не трогаем —
  живёт в csr0xbc до собственного prologue FN_A. Хвост зоны стаба
  (0x38d774–0x38d7d8) — нули (стоковые).
- Дифф v4→v5a: детур байт-в-бит; de-CRC код — только 33 слова стаб-зоны
  (9 новых + 24 обнулены); GUID-секции байт-в-бит v4; файл — только
  ITOC 0x03 raw + CRC ITOC-entry.
- md5 v5a: `5cbb4d7c54d832860e748fe24611d929`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты (DEV_INFO+MFG_INFO) baked,
  rebuild детерминирован. Полная слово-таблица + probe-матрица T17 —
  журнал task-16.

## v5b (C1-attempt: фильтр на live-доказанном слоте; task-18)

- Причина: T17 live-карта (матрица 8/8, два канала чтения) — посадка хвоста
  байт-линейная: input[k] → [r1+0x98+k] (доказано k∈{0x12,0x13,0x14});
  слот фильтра **[r1+0xaa]** = input[0x12..0x14), BE-полуслово, zext.
  k≥0x15 (зона маршал-райтеров) — гипотеза ⇒ **gauntlet обязателен**
  (реконсиляция 526415b).
- Фильтр: `ld.w r12,[r1+0xaa]` vs `set3 r13,zero,0x5332` (**MAGIC16**,
  1 слово — fuzz-T3 behavioral: set3 rd,zero,imm → rd=imm), cmp38_sel(2)
  eq32 (то же live-proven слово `0xE1806802`), b_f.cc0A → W_FAST.
  На магии: эхо полуслова → CR 0x2380, N (16-бит, input[0xC..0xE) через
  [r1+0xa4]) → CR 0x2384, push −0x40, copy N слов input+0x14 → [r1+0x20).
- Copy-loop: ФОРМА v2/v4 (do-while b_f.cc00, addi×2, subsi), но **2 пары
  ld.w/st.w на слово** (офсеты 0/2): ld.w/st.w — 16-битные операции
  (slaspec `*[ram]:2` + T17 live); одиночная пара v2/v4 при шаге 4
  копировала бы каждое второе полуслово (не всплыло: фильтры v2/v4 мертвы).
- **Gauntlet**: перед прыжком — `ld.w` первого скопированного полуслова
  ([r1+0x20]) vs `set3 r13,zero,0x2407` (hi-полуслово слова маркера
  0x24075332); мимо → pop + tail-jump FN_A (чистый сток-completion,
  мусор не исполняется никогда); совпадение → `ret.r r12` в payload
  (resume live-PC 0x00b8d7c0, как v2/v4).
- Стаб: **30 слов** (бюджет 34), clobber строго {r3,r11,r12,r13}: r5/r6-init
  и r4=result-адди сняты (маркер-лайт их не требует), restore-слова r4/r5/r6
  не нужны; ra-save (csr_r + st.d @S_RA) — lineage (мёртвый, безвредный);
  RESUME = pop + tail-jump (r3 мёртв: FN_A prologue сам читает csr0xbc —
  v5a-паттерн). Полная слово-таблица + декод — журнал task-18.
- input v5b (`payload.input_block_v5b`): `[0..4)=0x09320000,
  [4..8)=0, [8..0xC)=0 (TT=0 + tn=0 — tn-несущие гибнут ДО детура, T17),
  [0xC..0xE)=N (BE16, слова, 1..4), [0xE..0x12)=0, [0x12..0x14)=53 32,
  [0x14..0x24)=код`; маркер-лайт — прежние 4 слова (G5': 0x2388=S2OK).
- Синдром-ожидание (T19): ВСЕ кадры (fallthrough/echo/exec/negative) →
  сток-completion 0x1c2b78 (v5b не меняет путь завершения); наблюдаемость —
  CR-эхо (0x2380/0x2384) и маркер 0x2388. TRIG_CMD hex — журнал task-18.
- Дифф v5a→v5b: детур байт-в-бит; de-CRC код — только стаб-зона
  0x38d750–0x38d7c8; GUID-секции байт-в-бит v5a/v4; файл — только ITOC 0x03
  raw + CRC ITOC-entry. Хвост зоны (0x38d7c8–0x38d7d8) — стоковые нули.
- md5 v5b: `42bce965f49e2c62af72461207ab869f` (errata task-23: строка
  содержала до-ревью-фикшное `46af3b9a…`; актуальное значение — с N-guard,
  коммит 5ac9500, журнал task-18 §фикс и task-19 диспатч — сожжённый образ);
  verify --deep PASS, mstflint
  bootable PASS, GUID'ы карты baked (`mstflint -i q` показывает), rebuild
  детерминирован.

## v5c-A (frame-only probe; task-20, диагностика write-path-фриза)

- Причина: gauntlet-neg-кадр v5b ронял хост 2/2 (task-19/-debug2 на ядрах
  7.1.10/7.2.5); лидер-гипотеза RC1 — zero-precedent формы write-path
  (st.w/subsi/ld.w-комбинации). Задача v5c-A — бисекция push/pop от остального
  write-path: **M0 → push → M1 → pop → M2 → jump FN_A**, ничего больше
  (НЕТ saves/copy-loop/gauntlet/payload). После фриза CR 0x238C называет
  стадию: 0 — до M0 (шок, фильтр-регион); 1 — push; 2 — pop; 3 — выжил
  (RC1 сужается до saves/copy/gauntlet → v5c-B).
- Стаб: **21 слово** = префикс v5b w0-11 дословно (live-proven; иммедиаты
  b_f.cc0A пересчитаны на W_FAST@w20=0x38d7a0) + маркеры
  `set3 r12,zero,{1,2,3}` + `st.d r12,zero,0x238C` вокруг stock-идентичных
  push `703f0fc2` / pop `00210040` (185/185 точных сток-сайтов) + `jump
  FN_A` (0x95F80071). RC1-урок — у КАЖДОГО слова есть прецедент: 3 stock-exact,
  12 byte-exact live (v5b префикс + v5a-слово CR-0x238C `6c04638e`),
  ветки/jump — живые формы с пересчитанным imm, маркерные set3 — форма
  сток-прецедентна (rd=12: 362 сайта, скан T20) и v5b-live (guard-константа
  `200c0004` в чистом G-echo). Clobber {r3,r11,r12,r13}+r1(push/pop, баланс).
  Полная слово-таблица + декод + интерпретация — журнал task-20.
- input: прежний v5b (`payload.input_block_v5b`); **тест-кадр live-фазы** —
  gauntlet-neg (единственный ронявший хост):
  `09320000000000000000000000040000000053322406533220e74f4b6c043b8afc001825`
  (byte-exact верифицирован тестом TestTrigV5C).
- Дифф v5b→v5cA: детур байт-в-бит; de-CRC код — 23 слова зоны стаба
  0x38d764–0x38d7d0 (префикс w0-4/w6-10 совпадает байт-в-байт); GUID-секции
  байт-в-байт; файл — только ITOC 0x03 raw + CRC ITOC-entry. Хвост зоны
  0x38d7a4–0x38d7d8 — стоковые нули.
- md5 v5cA: `49a55c3fb78c4fbf3a7417cb38dc74cf`; verify --deep PASS, mstflint
  bootable PASS, GUID'ы карты baked (`mstflint -i q`), rebuild
  детерминирован. Burn/live — фаза 2 (GO владельца, D3-процедура).

## v5c-B (full-write-path instrumented; task-21, диагностика фриза)

- Причина: v5c-A (task-20 Phase 2, live ×2) доказал префикс/push/pop
  невиновными на gauntlet-neg-кадре (ронявшем хост 2/2 на v5b); задача
  v5c-B — указать фриз-группу среди {saves, copy-loop, gauntlet}:
  ВЕСЬ v5b write-path дословно (подозреваемые слова побайтово = v5b:
  ra-save `6c201802`, dst-init `002c0020`, цикл `6563/6d80`×2 + addi×2 +
  subsi `15ad0001` + back-edge `a400fff8` (imm −7→−8, цель та же),
  gauntlet `642c0021/200d2407/e1806802/a40a0001`) + маркеры стадий.
- Маркеры: M1=2 после save, M2=3 после цикла — `set3 r12,zero,V` +
  `st.d r12,zero,0x238C` (слово `6c04638e` v5a-live); внутри-итерационный
  счётчик `st.d r13,zero,0x2388` (`6c046b8a`; rt/rs-поля = v5b-live
  N-эхо `6c046b86`, CR-цель = v5a-live probe-3) после 2-й st.w — значения
  4/3/2/1 по итерациям. Префикс w0-11 == v5cA/v5b (иммедиаты веток на
  W_FAST@w33=0x38d7d4).
- Интерпретация (фриз → CR 0x238C): <2 = saves (push невиновен);
  2 = copy-loop (0x2388 = итерация); 3 = gauntlet (pop невиновен);
  чистый completion = выжил (RC1 write-path опровергнут). Полная таблица +
  протокол — журнал task-21.
- Бюджет-разрешение (жёсткая зона 34): максимальный дизайн брифа (M0..M4 +
  gauntlet + payload-jump + счётчик = 43 слова) не влезает; сняты M0/M4
  (брекетки оправданных push/pop) и матч-только M3+payload-блок ⇒ ровно
  34 СО счётчиком; на gauntlet-MATCH фоллтру тоже попадает в pop (payload
  не исполняется никогда). Обоснование — журнал task-21 §Step 0.
- Дифф v5cA→v5cB: детур байт-в-бит; de-CRC код — 24 слова зоны стаба
  0x38d764–0x38d7d4 (префикс w0-4/w6-10 байт-в-байт v5cA); GUID-секции
  байт-в-байт; файл — 88 байт, только ITOC 0x03 raw + CRC ITOC-entry.
  Зона заполнена 34/34 (хвоста нет).
- TRIG (live-фаза 2, порядок): neg-кадр ПЕРВЫМ
  (`0932…5332 24065332…`, gauntlet miss = фриз-репродуктор), затем exec
  (hi=0x2407, match; на v5cB тот же путь) — byte-exact тест TestTrigV5CB.
- md5 v5cB: `4a4ac5b8cd878ccfb474c7e371a6d524`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked (`mstflint -i q`), rebuild
  детерминирован. Burn/live — фаза 2 (GO владельца, D3-процедура).

## v5d (stock-conformance copy path, C1-candidate; task-23)

- Причина: аудит task-22 (review-approved) не нашёл smoking gun — все
  четыре гипотезы (H-LOOP/H-ADDR/H-TRAP/H-SAVE) рефутированы; остаточные
  подозреваемые КОНВЕНЦИОННЫЕ: st.w rt=3∧rs=12 (0/1947, топ) и
  subsi rd=13 (0/37907, r13 — зарезервированный сток-ABI регистр).
  v5d заменяет дата-путь копи-цикла на сток-конформный.
- Дифф v5b→v5d — ТОЛЬКО копи-слова: две 16-битные ld.w/st.w-пары →
  ОДНА 32-битная `ld.d r3,[r11+0]` + `st.d r3,[r12+0]` (оба слова
  byte-exact сток: ×1 и ×46 код-сайтов, все off=0; комбо ld.d
  rs=11∧rd=3 ×2); strides addi +4 и subsi r13,r13,1 на месте
  (последний — ЕДИНСТВЕННОЕ 0-прецедентное поле, принятый constrained
  minimum; remap баз на r13 хуже — 0/71030); back-edge imm −7→−5
  (0xA400FFFB — сам сток ×314). Зафиксированный shape-остаток: смежная
  пара ld.d r3→st.d r3 в стоке 0 раз (поля прецедентны, форма нова).
- M-marker `set3 r12,zero,7` + `st.d r12,zero,0x238C` после выхода из
  цикла (liveness «copy done»; 0x6C04638E — v5a-live byte-exact, set3
  rd=12 — v5cA-live ×2 / 362 сток-сайта): сэкономленные парой 2 слова
  его оплачивают ⇒ gauntlet/payload/resume/W_FAST и иммедиаты веток
  префикса остаются v5b BYTE-EXACT на тех же индексах/адресах
  (W_FAST@w32=0x38d7d0). 33 из 34 слов зоны.
- Интерпретация live-фазы (кадры — прежние v5b TRIG, byte-exact):
  чистое завершение + **0x2388=0x53324F4B ⇒ C1** (0x238C=7 — копи
  завершено); фриз на neg/exec при всех-прецедентных полях ⇒ **RC1
  исключён** → RC2/RC3. Полная слово-таблица + классы прецедентов —
  журнал task-23.
- md5 v5d: `b34ea9645b574f7e8e4c96ef29bc0593`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked, rebuild детерминирован.
  Burn/live — фаза 2 (GO владельца, D3-процедура).

## v5e (escalation N-gates bisection; task-25)

- Причина: v5d ФРОЗИТ при всех byte-exact-stock копи-словах ⇒ RC1
  (zero-precedent) исключён владельцем; аудит task-24 (combo/RC2/RC3) не
  нашёл новых 0-прецедентов и спроектировал v5e (rev.2, review-driven):
  ОДИН burn даёт блок-атрибуцию фриза — фриз на кадре N=k называет блок.
- Дизайн: префикс w0-w8 = live-exact v5b (фильтр/эхо/N+эхо 0x2384); N-guard
  v5b заменён эскалацией: push → saves (v5d-verbatim 0-combo suspect!) →
  L2-гейт `set3 r12,zero,2` (v5cA-live M1) + `E1A06002` (v5b-live guard)
  + `b_t.cc0A → TAIL` (сток ×56) → dst-init (v5d-verbatim suspect) + пара
  `ld.d/st.d` (v5d-verbatim suspects) → L3-гейт `set3 r12,zero,3`
  (v5cA-live M2) + cmp38 + `b_t.cc0A` (×75) → dst RE-INIT `addi r12,r1,0x20`
  (erratum-фикс rev.2: НЕ `ld.w` — гейты клобберят r12, ld.w дал бы
  абсолютные EA) → цикл v5d-VERBATIM (w21-w26 == v5d w15-w20) → общий
  TAIL: маркер `st.d r13,zero,0x238C` (echo-форма с ретаргетом offset;
  значения N=2→2, N=3→3, N=4→0, N=1→0) → pop → W_FAST последним словом
  (w29 = 0x38d7c4). **30 из 34** слов зоны; каждый гейт-сток-точен или
  live-exact (cmp38_sel(2)-гейты: все туплы 0-stock — live-lineage only,
  верификация туплов ПЕРВЫМ делом по правилу ревью).
- Кадры (payload.py не менялся; N=2/N=3 — новые входы input_block_v5b):
  fallthrough → echo-N1 (`…0001…5332 fc001825`) → neg-N2 (`…0002…5332
  24065332 20e74f4b`) → neg-N3 (`…0003… +6c043b8a`) → neg-N4 (byte-exact
  freeze-репродьюсер v5b/v5cB/v5d). Протокол: один boot, фриз = конец
  сессии = измерение. Интерпретация: фриз@N=2 ⇒ **SAVES**; @N=3 ⇒
  **WRITE-PAIR** (dst-init vs pair — дизамбигуатор переносом L3-гейта);
  @N=4 ⇒ **LOOP**; все чисты ⇒ write-path оправдан ⇒ следующие
  подозреваемые gauntlet/M/v5d-only или H-class системика.
- Остатки (журнал task-25): echo-N1 гоняет write-path на глубине 1
  (идемпотентная 1-слово запись в свой фрейм); garbage-N guard НЕТ
  (кадры только билдером, payload.py ассертит N∈[1..4]); b_t.cc0A в
  lineage ещё не live-taken (сток-класс ×2315, adjacency ×15, слова
  ×56/×75). Симуляция путей register-true (портирована из task-24
  verify_v5e2) — в тестах; ноль абсолютных non-CR записей на всех путях.
- md5 v5e: `149e7bfbd8cdab0d2bd7d64693e4997d`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked, rebuild детерминирован.
  Полная слово-таблица + таблицы путей + остатки — журнал task-25.
  Burn/live — фаза 2 (GO владельца, D3-процедура).

## v5f (skip-idiom-gated escalation; task-27)

- Причина: бисекция task-25 дала freeze-#6 — neg-N2 (v5e) froze на
  ПЕРВОМ taken `b_t.cc0A` (w13 0xA00A000E → TAIL); аудит task-26
  вердикт: взятый op=0x28 на 4030/MT28800 недоказан и должен считаться
  небезопасным.  v5f заменяет ОБА гейта на сток «skip-идиому»
  `[cmp38; b_f.cc0A +2; jump TAIL]`: равенство → b_f НЕ-взят →
  исполняется БЕЗУСЛОВНЫЙ jump TAIL; неравенство → b_f взят +2
  (b_f.cc0A при latch=FALSE — единственный live-чистый taken-класс на
  4030, ×5 boots через fallthrough w5).
- Дизайн: префикс w0-w10 = v5e byte-exact (только imm w5 +24→+26 —
  W_FAST сдвинулся на w31; 0xA40A001A сток ×10); L2-гейт w11-w14
  (set3 M1 + cmp38 guard + skip 0xA40A0002 сток ×94 (74/94 сразу после
  op36/op38) + jump 0x9500000F ×222); dst-init/пара — v5e-слова на +1
  слово; L3-гейт w18-w21 (set3 M2 + cmp38 + skip ×94 + jump 0x95000008
  ×365); dst RE-INIT (rev.2-фикс) → цикл v5d-VERBATIM (w23-w28 == v5d
  w15-w20) → общий TAIL: маркер `st.d r13,zero,0x238C` @w29 (N=2→2 /
  N=3→3 / N=4→0 / N=1→0) → pop → W_FAST последним (w31 = 0x38d7cc).
  **32 из 34** слов зоны; ноль b_t-слов в стабе (freeze-класс устранён
  из множества путей); удалены 0xA00A000E (×56) / 0xA00A0008 (×75).
- Симулятор путей расширен: op=0x25 декодируется (irisc_dis
  `off+s24*4`) и внутристабовые jump-цели СОПРОВОЖДАЮТСЯ (выход только
  за пределы стаба = FN_A) — пути N=2/N=3 проходят до конца; каждый
  взятый условный переход логируется (слово/op/cc/latch): на всех 5
  путях НЕТ взятых b_t и НЕТ взятых при latch=TRUE; путь N=2 — НОЛЬ
  взятых условных вообще; N=4 — впервые взятый back-edge b_f.cc00 ×3
  (документированный остаток: фриз@N=4 называет класс).
- Кадры = v5e byte-exact (payload.py не менялся).  Интерпретация:
  фриз@N=2/3 ⇒ класс skip-идиомы/jump (saves/pair оправданы echo-N1);
  фриз@N=4 ⇒ loop-back-edge-taken назван (→ размотка v5g); все чисты ⇒
  gauntlet/M/v5d-only-дельты → v5g C1-попытка.
- md5 v5f: `1cd0090582d9f2d42a814f8b396a0ab4`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked, rebuild детерминирован.
  Слово-таблица + таблицы путей + остатки — журнал task-27.
  Burn/live — фаза 2 (GO владельца, D3-процедура).  Live-вердикт
  (task-27 Phase 2): freeze@N=2 ВОСПРОИЗВЛЁДЖЁН на чистом skip-идиомном
  пути (ноль b_t, ноль взятых условных) — теория b_t-taken опровергнута;
  названный класс skip-idiom/jump; H-class системика открыта.

## v5g (linear fork-test; task-28)

- Причина: все 5 фризов несут ПЕРЁДНЮЮ block-переброску/jump с ПОЗДНЕЙ
  позиции стаба (v5b/v5cB/v5d N=4: gauntlet-skip; v5e N=2: taken b_t
  +14; v5f N=2: taken jump +15), а все чистые magic-прогоны были
  ЛИНЕЙНЫ (v5cA; echo-N1 ×2).  v5g = поток v5b МИНУС gauntlet МИНУС
  payload-блок МИНУС все N-гейты — полностью линейный; fork-test:
  фриз = INPUT (tail-байты/N≥2), все чисты = SKIP (переброски).
- Дизайн: префикс w0-w10 = v5e/v5f byte-exact (только imm w5 +26→+17 —
  W_FAST сдвинулся на w22; 0xA40A0011 сток ×15); фильтр magic + принятие
  всех N∈{1..4} (N-guard нет); dst-init + одна ld.d/st.d пара
  (v5d-слова) → цикл v5d-VERBATIM (w14-w19 == v5d w15-w20; ×N итераций,
  back-edge b_f.cc00 взят ×(N−1) при latch=FALSE — ЕДИНСТВЕННО возможный
  взятый условный на magic-пути) → TAIL-маркер `st.d r13,zero,0x238C`
  (r13=0 после цикла при любом N≥1 — неинформативно, live-form для
  униформы) → pop → W_FAST последним (w22 = 0x38d7a8).  **23 из 34**
  слов зоны (v5f 32 − L2 4 − L3 4 − dst re-init 1); ноль b_t-слов,
  единственный jump-слово = W_FAST, условные слова = только w5 и w19.
- Маркер 0x238C всегда 0 на magic — N различается ТОЛЬКО порядком
  протокола (echo первым, потом эскалация N=2/3/4; фриз = стоп).
- Кадры = v5e/v5f byte-exact (payload.py не менялся).  Интерпретация:
  N=1 (echo, 24B) — регрессия, ждать чисто (×2 lineage); фриз@N=2+
  (кадры с payload-tail 28/32/36B) ⇒ H-INPUT (tail-байты/N≥2; прямое
  управление потоком оправдано — его нет); все чисты ⇒ H-SKIP
  (переброски — триггер; write-path+loop+back-edge+input-tails все
  реабилитированы, v5g = чистейший C1-базлайн).
- md5 v5g: `4c5ad7353cdfe0be66d61b1d3578100c`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked, rebuild детерминирован.
  Слово-таблица + decode + branch-inventory + fork-интерпретация —
  журнал task-28.  Burn/live — фаза 2 (GO владельца, D3-процедура).
  Live-вердикт (task-28 Phase 2): фриз@N=2 воспроизведён на полностью
  линейном v5g (ноль forward-управления) — skip/jump-теория исчерпана;
  SAVE-слово `st.d r3,r1,0` (единственный выживший 0-combo
  rt=3∧rs=r1∧off=0) — общий знаменатель всех 8 фризов → v5h.

## v5h (no-save linear stub; task-29)

- Причина: named-suspect тест — SAVE-слово `st.d r3,r1,0x0` (v5g w10 =
  0x6C201802, сток-перепись ×0) выполнялось на КАЖДОМ фриз-пути И на
  каждом чистом magic-пути (ledger + журнал task-28 фаза-2: фриз@N=2 на
  полностью линейном v5g); r3 мёртв на детуре (R3) — сейв был
  вестигиальной паранойей.  v5h = v5g МИНУС ровно это слово.
- Дизайн: префикс w0-w4/w6-w9 = v5g byte-exact (только imm w5 +17→+16 —
  W_FAST сдвинулся на w21; 0xA40A0010 сток ×22) → push → [БЕЗ СЕЙВА] →
  dst-init (w10, слово v5d; слот сейва ПЕРЕИСПОЛЬЗОВАН) → пара ld.d/
  st.d (слова v5d) → цикл v5d-VERBATIM (w13-w18 == v5d w15-w20;
  back-edge-слово 0xA400FFFB НЕ ИЗМЕНИЛОСЬ — офсет −5 относительный,
  оба конца сдвинулись вместе) → TAIL-маркер `st.d r13,zero,0x238C` →
  pop → W_FAST последним (w21 = 0x38d7a4, 0x95F80070 live-form ×0).
  **22 из 34** слов зоны; ноль b_t; единственный jump = W_FAST;
  условные = фильтр w5 + back-edge w18.
- Diff-vs-v5g (ассертится): ровно слово сейва (0x6C201802, ×1→×0) +
  два позиционных imm (w5 0xA40A0011→0xA40A0010; W_FAST
  0x95F8006F→0x95F80070); тело w10-w19 = v5g w11-w20 byte-exact.
- Кадры = v5g byte-exact (payload.py не менялся).  Интерпретация:
  echo-N1 — регрессия (ждать чисто, ×3 lineage); neg-N2/3/4 (tail-кадры)
  чисто ⇒ **SAVE×TAIL назван** (0-combo-сейв — триггер; write-path
  ПОЛНОСТЬЮ реабилитирован → v5i-C1: v5h + gauntlet + payload без
  сейва); фриз ⇒ глубже: pair/loop × tail-CONTENT (копируемые ЗНАЧЕНИЯ
  важны; дизамбигуатор — нейтральные константы vs tail-байты).
- md5 v5h: `6d92bae9955107ef756355ac1d25fdc7`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked, rebuild детерминирован.
  Слово-таблица + diff-таблица + branch-inventory — журнал task-29.
  Burn/live — фаза 2 (GO владельца, D3-процедура).

## v5i (neutral-write discriminator; task-31)

- Причина: freeze #9 (журнал task-29 фаза-2) — фриз@N=2 на v5h (v5g
  МИНУС сейв) ⇒ сейв и write-path-механика НЕ триггер; дискриминатор:
  tail-кадр × ЛЮБОЙ лишний write в пуш-фрейм ⇒ фриз (сейв ИЛИ копии);
  push-ra + CR-writes всегда чисты.  v5i = v5h с блоком пара+цикл
  ЗАМЕНЁННЫМ на ОДИН НЕЙТРАЛЬНО-КОНСТАНТНЫЙ write во фрейм.
- Дизайн: префикс w0-w9 = v5h byte-exact (только imm w5 +16→+9 —
  W_FAST сдвинулся на w14; 0xA40A0009 сток ×48 — лучший счёт линии) →
  `set3 r12,zero,0xA5A5` (w10) → `st.d r12,r1,0x30` (w11; сток ×1 —
  тупл прецедентен, fallback-клауза брифа не сработала; класс
  st.d rt=12,rs=r1 ×26; слот 0x30 — свободный, ничем раньше не писан)
  → TAIL-маркер `st.d r13,zero,0x238C` (слово v5h НЕ ИЗМЕНЕНО) → pop →
  W_FAST последним (w14 = 0x38d788, 0x95F80077 live-form ×0).
  **15 из 34** слов; ноль b_t; единственный jump = W_FAST; условные =
  ТОЛЬКО фильтр w5 — back-edge НЕТ (цикл удалён); N только эхом
  (0x2384=N), в управлении не участвует; НИКАКИХ input-значений в
  write-path (set3 zero-reg+imm непоср. кормит store).
- Erratum (задокументировано): r13=N доходит до TAIL-маркера (цикл,
  обнулявший счётчик, удалён) ⇒ чистое завершение даёт 0x238C=N;
  фриз ⇒ 0x238C остаётся 0 (fresh baseline; маркер — последний
  CR-write на пути).  Word-level мандат «TAIL unchanged» брифа
  приоритетнее его сводки «0x238C=0».
- Diff-vs-v5h (ассертится): удалён блок копирования (dst-init + пара +
  цикл: 8 различных слов, пара ×2) + 2 позиционных imm (w5
  0xA40A0010→0xA40A0009; W_FAST 0x95F80070→0x95F80077); вставлена
  нейтральная пара (0x200CA5A5 + 0x6C206032).
- Кадры = v5h byte-exact (payload.py не менялся); код-окно НЕ читается
  вовсе (ld-слова только 0xaa/0xa4).  Интерпретация: echo-N1 —
  регрессия (ждать чисто, ×4 lineage); neg-N2/3/4 — путь
  ИДЕНТИЧЕН для всех N (префикс+push+НЕЙТРАЛЬНЫЙ-WRITE+маркер+pop+
  jump): фриз ⇒ **H-FRAMEGUARD** (любой лишний frame-write ×
  tail-кадр, контент-независимо → C1 обязан избегать writes во фрейм
  целиком, task-30 RE); чисто ⇒ **H-CONTENT** (копируемые ЗНАЧЕНИЯ
  были триггером → C1 = copy-free ИЛИ санитайз/валидация до копии).
- md5 v5i: `3622bd84bd0c41b67e4812f65bdddbf6`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked, rebuild детерминирован.
  Слово-таблица + diff-таблица + branch-inventory — журнал task-31.
  Burn/live — фаза 2 (GO владельца, D3-процедура).  Live-вердикт
  (task-31 фаза-2): все гейты чисты — H-FRAMEGUARD опровергнут; НОЛЬ
  доп-записей во фрейм = безопасный класс (push-ra + CR-writes чисты
  всегда; одна нейтральная запись тоже чиста).

## v5j (exec-from-input C1 attempt; task-32; rev.2 — Exit-C, ревью T32)

- Причина: пивот C1 по итогам всей линейки фризов — единственный
  live-доказанный безопасный класс письма: НОЛЬ доп-записей в кадр
  (push-ra + CR-записи чисты всегда, v5i фаза-2).  v5j ИСПОЛНЯЕТ
  payload IN-PLACE из зоны посадки input: ноль копий, ноль записи
  во фрейм (дизайн — журнал task-30 Q4-скетч + errata f0e4804).
  **Rev.2 (Exit-C, ревью T32)**: устранены Critical #1 (p4 прыгал в
  файловое 0x18d964 вместо live 0x98d964 — off 0x800000), Important
  #2 (w10 rs=0 ЛИНКУЕТ: csr0xbc := W_FAST ⇒ цикл FN_A↔W_FAST),
  Important #3 (байты p4 в зоне коррупции T2 k≥0x24).
- Дизайн: префикс w0-w8 == v5i byte-exact (только imm w5 +9→+6 —
  W_FAST сдвинулся на w11; 0xA40A0006 сток ×70 — лучший счёт линии);
  НЕТ push/save/copy/neutral-write (единственные записи — CR-эхо,
  always-clean класс), НЕТ N-guard/gauntlet (N только эхо 0x2384=N).
  w9 = `addi r11,r1,0xac` (слово w1; payload-ptr перед передачей;
  посадка 0x98+0x14=0xAC) → w10 = `ret.r zero,r8,r11` (**0xFD005825**)
  — ЕДИНСТВЕННАЯ передача, rs=8 computed-jr класс **БЕЗ ЛИНКА**
  (csr0xbc хранит до-детурный ra 0x0e4380; слово STOCK-EXACT ×3,
  класс ×8986 live — канонический return-идиом, инвентарь task-30;
  НЕ rs=0 jalr ×294 — тот линкует) → W_FAST `jump FN_A` последним
  (w11 = 0x38d77c, 0x95F8007A live-form ×0).  **12 из 34** слов;
  ноль b_t; условное = только фильтр w5.
- Payload (`payload.payload_v5j`, rev.2: **4 слова**, кадр **36B** =
  стандартный neg-frame размер, все байты k≤0x23 — внутри
  strictly-clean окна T2 (потолок окна 0x38), экспозиции зоны
  коррупции НЕТ): p0 `set3 r12,r12,0x4f4b` (lo16 insert) + p1
  `set2 r12,r12,0x5332` (hi16 insert — slaspec-семантика;
  ДЕТЕРМИНИРОВАНО, вход r12 не важен) → r12=0x53324F4B; p2 `st.d
  r12,zero,0x2388` = S2OK (v5a-live слово) — ПОЛНЫЙ C1-сигнал,
  самовалидируется (эхо посадки 0x238c СНЯТО); p3 = `jump 0x98d964`
  — на **LIVE FN_A** (= file 0x18d964 + 0x800000) с live PC r1+0xb8
  (k=0x20): позиционно-зависим от гипотезы базы стека (дефолт SP-init
  cpu0 0x7d1ff8; imm +0x6EE2D, слово 0x9506EE2D; **s24 влезает для
  ВСЕХ баз 0x7d1ff8..0x7ffff8** — худший imm 0x6EE2D, запас
  0x7911D2 слов; sweep-ассерт в тестах + fail-loud в билдере).
- **Semantика выхода (Exit-C):** p3 → FN_A ret.d → csr0xbc =
  до-детурный ra (на всём пути НЕТ линка: w10 rs=8, p3 = jump) →
  стоковый возврат в диспетчер — ТА ЖЕ семантика, что у каждого
  чистого прогона v5-серии (×dozens live). Ни линка, ни frame-write,
  ни байтов за k=0x23.
- TRIG-кадр (36B, N=4 — эхо, управлением НЕ используется):
  `0932000000000000000000000004000000005332218c4f4b258c53326c04638a9506ee2d`;
  ЕДИНСТВЕННАЯ безопасная magic-форма (каждый magic-кадр уходит в
  посадку — короткие кадры линейки невалидны).  Fallthrough-кадр —
  прежний 36B lineage.
- Интерпретация (rev.2): чисто + 0x2388=0x53324F4B ⇒ **FULL C1**
  (фриз не ожидается — выход = доказанный класс); фриз + 0x2388=S2OK
  читаем ⇒ payload исполнился, выход сошёл (investigate — неверная
  база p3); фриз + 0x2388=0 ⇒ класс stack-exec/w10 не прошёл; чисто +
  0x2388=0 ⇒ w10-посадка/fetch не дошёл (эхо 0x2380/0x2384 различают,
  что префикс отработал).
- Дифф v5i→v5j (ассертится): удалён frame-блок (push + нейтральная
  пара + TAIL-маркер + pop: 7 слов) + 2 позиционных imm (w5
  0xA40A0009→0xA40A0006; W_FAST 0x95F80077→0x95F8007A); вставлены
  передача w10 (0xFD005825, stock ×3) и w9 (0x002B00AC, ×1→×2).
- md5 v5j rev.2: `4732d30c93573f7c770b96287a55ff90` (rev.1
  `f83eaec2dcc1fedcccb0e54785a51683` отозвана ревью); verify --deep
  PASS, mstflint bootable PASS, GUID'ы карты baked, rebuild
  детерминирован.  Слово-таблицы + decode + sim-контракты (live-space
  выход, no-link csr0xbc, sweep баз) — журнал task-32 §Errata+rev.2.
  Burn/live — фаза 2 (GO владельца, D3-процедура).
- **Фаза 2 (live, 2026-10-01 23:24–23:36 UTC): burn PASS (Phase 1);
  fallthrough PASS (3/0x1c2b78, CR 0×4); C1-TRIG = ФРИЗ (hang > 60 s,
  kill) + CR-запись из payload: 0x2380=0x5332 / 0x2384=4 / 0x2388 =
  `0x53325F7B` / 0x238C=0 (baseline 0/0/0/0; cr-space жив, S0=badc0001;
  хост жив — тихий wedge, класс task-07, НЕ смерть-хоста #9).**
  Вердикт: **exec-from-input ДОКАЗАН (первый в линейке)** — w9/w10
  no-link передача чиста, ≥3 payload-слова исполнены из зоны посадки
  (p1 hi-вставка точна, p2 стора в 0x2388 точна, fetch BE, I/D-
  когерентность OK); **FULL C1 не достигнут** — lo16-аномалия p0
  (0x5F7B ≠ 0x4F4B; гипотезы: доставка k=0x16..0x18 [непроверенная зона
  T17] / set3-rs=rd-writeback / OR-семантика — дискриминатора нет);
  выход сошёл на p3 (базо-зависимость r1 ≠ 0x7d1ff8 → коорд. note:
  ветка Exit-D — и/или доставка k=0x20..0x24). Echo-N1 в v5j-сессии
  ВЫПРОЩЕН по контракту (единственная magic-форма = полный TRIG; в
  echo-кадре на k=0x14 сидит `ret.r zero,zero,r3` — неконтролируемый
  выход; решение задокументировано ДО прогонов). Идемпотентность/post-map
  не выполнялись (фриз = конец сессии, no-retry). Детали+таблицы —
  журнал task-32 §v5j фаза 2.

## v5k rev.2 (exact S2OK + эпилог-реплика; task-33 — вторая C1-попытка,
фикс ревью T33)

- Причина rev.2 (ревью коммита 40d902a, подтверждено декодом базы):
  **Critical-1** — Exit-D rev.1 неверифицирован: детур-путь
  (0x0e4258 пуш 0xf8 → 0x0e42b8 линк-переход → 0x0e4310 → call
  0xebc9c @0x0e4328 → call 0xcaec0 @0x0e4358 → детур 0x0e437c)
  НИКОГДА не попает фрейм — детур-тайм r1 = R−0xf8, [r1+4] =
  ВНУТРЕННИЙ слот (последний вложенный resume **0x8E435C**);
  регион [0x0e435c,0x0e437c) линеен в детур-колл ⇒ p3 rev.1
  ре-входил в детур = **детерминированный livelock**.
  **Important-2** — r17-r23 (сейвы @0x0e425c-74, реставрации
  ТОЛЬКО на эпилог-пути 0x0e42e8-0x0e4300) текли на любом
  не-эпилогном выходе.
- **Fix (дизайн ревью — stub-side epilogue replica):** стаб несёт
  10-словную **byte-exact копию собственного эпилога fn**
  (@0x0e42e8..0x0e430c: 7 ресторов r23..r17 из [r1+0xdc..0xf4] —
  зеркало сейвов; `addi r1,r1,0xf8` поп — сток-слово, ЗАПИСЬ
  РЕГИСТРА SP; `ld.d r3,r1,0x4` — ТЕПЕРЬ внешний [R+4] = истинный
  ra диспетчера (пролог @0x0e4254 до пуша; нетронут вложенными);
  `ret.r zero,r8,r3` — финальное слово fn) и **пре-лоадит r3
  абсолютным live-адресом реплики** ДО передачи: w10 `set3
  r3,ZERO,0xd784` (rs=zero — lo ЧИСТ при ОБЕИХ семантиках, паттерн
  S2OK p0/p1) → w11 `set2 r3,r3,0x00b8` (hi-insert против hi16=0 —
  согласовано; остаток r3=0x8E4380 от w0 протечь не может) ⇒ r3 =
  0xB8D784 = зона стаба — **базо-независимость by construction**.
  Payload p3 = `ret.r zero,r8,r3` (БЕЗ ИЗМЕНЕНИЙ, 0xFD001825,
  сток ×8346) выходит в реплику: fn-эпилог исполнен — регистры
  реставрированы, фрейм попнут, возврат диспетчеру.  Livelock и
  утечка r17-r23 ОТСУТСТВУЮТ by design (одинарный транзит; внешний
  ra потребляется ровно один раз).  r4-эквивалентность: реплика
  опускает `or r4,r19,r19` @0x0e42e4 — на детуре r4=0 уже
  (`addi r4,zero,0` @0x0e4374) == сток post-FN_A BadParam.
- Стаб (24 слова; W_FAST `jump FN_A` ПОСЛЕДНИМ, w23 = 0x38d7ac,
  0x95F8006E live-form ×0): префикс w0-w8 == v5j byte-exact (только
  imm w5 +6→+18 — 0xA40A0012 сток ×27); w9 = `addi r11,r1,0xac`
  (payload-ptr); w10/w11 сбор r3; w12 = `ret.r zero,r8,r11`
  (0xFD005825, сток ×3, rs=8 no-link) — ЕДИНСТВЕННАЯ передача;
  w13-w22 РЕПЛИКА — ВСЕ 10 слов byte-exact сток (цензус ×6/×7/×6/
  ×5/×5/×3/×2/×17/×8347/×8346 — сильнейший класс прецедентов
  линейки; верифицируется на каждой сборке против базы:
 construction-check в build_code).  НОЛЬ b_t; НОЛЬ записей в
  память кроме CR-эхо w6/w8 на любом пути (ресторы — ЧТЕНИЯ; поп —
  регистровое слово); r4/r5/r6/r14-r16 не тронуты; r17-r23 —
  только репликой (семантика собственного эпилога fn).
- Payload (`payload.payload_v5k`, 4 слова НЕ ИЗМЕНЕНЫ, кадр 36B,
  k=0x14..0x24): p0 set3-rs-zero-lo + p1 set2-hi → r12=0x53324F4B
  (Fix 1 — точная сборка S2OK из любого остатка, живой root-cause
  0x5332|0x4F4B=0x5F7B); p2 `st.d r12,zero,0x2388` = S2OK —
  ПОЛНЫЙ C1-сигнал; p3 выход в реплику через r3.
- TRIG-кадр (36B, N=4 — эхо, управлением НЕ используется):
  `0932000000000000000000000004000000005332` +
  `200c4f4b258c53326c04638afd001825`; **ОДИН фиксированный кадр
  для ВСЕХ SP-баз**.  Fallthrough — прежний 36B lineage.
- Sim-контракты rev.2 (модель фрейма fn: внутренний [r1+4] =
  0x8E435C-яд, внешний [r1+0xf8+4] = сид диспетчера-ра, слоты
  сейвов, r17-r23 клоббернуты на входе; ret.r в зону стаба =
  продолжение слов — реплика исполняется в прогоне):
  rev.1-livelock witness (13-словный rev.1 стаб выходит на
  0x8E435C + декод-линейность региона ⇒ ре-вход в детур на HW);
  pop-ДО-внешнего-чтения (step-log); r17-r23 реставрированы из
  своих слотов в сток-порядке; выход = внешний сид, никогда
  внутренний; sweep 16 SP-баз фиксированными словами — везде
  выход/поп/ресторы/S2OK; r3-сбор точен при OR-семантики из
  реального остатка (witness неверной формы 0x00BED784).
- Дифф v5j→v5k rev.2 (ассертится): + пара r3-сбора (0x2003D784
  live-form set3-rs-zero-класс ×7348 + 0x246300B8 live-form) +
  10 слов реплики (все сток) + 2 позиционных imm (w5
  0xA40A0006→0xA40A0012; W_FAST 0x95F8007A→0x95F8006E); всё
  прочее идентично.
- Интерпретация: чисто + 0x2388=0x53324F4B ⇒ **FULL C1** (выход =
  реплика эпилога fn); чисто + ≠S2OK ⇒ сборка/доставка (значение
  CR назовёт: снова 0x53325F7B = OR+остаток; иное = доставка p0);
  card-wedge/host-alive + S2OK читаем ⇒ проблема реплики/возврата
  (диагностируемо); host-freeze ⇒ новый класс (неожиданно — ноль
  записей во фрейм); **сигнатуры livelock НЕТ by design**.
- md5 v5k rev.2: `c7b20098aa3b3a18e4bed540eebcf76d` (rev.1
  `cab57b60bc01523c450674bc634c6861` отозвана ревью — livelock);
  verify --deep PASS, mstflint bootable PASS, GUID'ы карты baked,
  rebuild детерминирован.  Слово-таблицы + decode + цензус +
  sim-контракты + errata — журнал task-33 §Errata+rev.2.
  Burn/live — координатор (off-line задача; карта идёт в FNP для
  ЭТОГО burn).

## v5l (call-site resume exit; task-34 — третья C1-попытка,
clean-completion)

- Основание (журнал task-33 фаза-2, commit bf0157c): **C1-критерий
  ДОСТИГНУТ live — CR 0x2388 = 0x53324F4B ТОЧНО**, payload 4/4
  исполнены из зоны посадки input (Fix 1 rs=zero подтверждён,
  v5j-аномалия 0x5F7B устранена); карта wedged НА/ПОСЛЕ p3 — реплика
  пропустила ТЕЛО fn после call-сайта, которое строит QUERY-
  completion (гипотеза (i) фриза).
- **Дизайн: v5k rev.2 МИНУС реплика, r3 = call-site resume.** Стаб
  пре-лоадит r3 = **0x008E4380** (= PC_BASE + детур 0x0E437C + 4 —
  resume задетуренного `call FN_A'; значение csr0xbc на входе в
  детур; значение, через которое возвращается сам сток-FN_A: пролог
  FN_A `csr.r r3,csr0xbc` @0x18d964 — БАЙТ-ЭКЗАКТ w0 стаба): w10
  `set3 r3,ZERO,0x4380` (rs=zero — ЧИСТО при ОБЕИХ семантиках,
  паттерн v5k) → w11 `set2 r3,r3,0x008e` (hi-insert; остаток w0 УЖЕ
  0x8E4380 — пара перестраивает значение ЯВНО, детерминированно при
  любом остатке).  Payload p3 `ret.r zero,r8,r3` (БЕЗ ИЗМЕНЕНИЙ,
  0xFD001825, сток ×8346) возвращает payload **В ТЕЛО fn** в точке
  возобновления — как вернул бы FN_A.
- **Сток-путь после resume (декод базы)**: 0x0E4380 `or r19,r4,r4`
  (маршал результата FN_A; наш r4=0 — v5i-документированная сток-
  настройка аргумента `addi r4,zero,0` @0x0E4374 == сток post-FN_A
  BadParam) → 0x0E4384 `subsi r4,r19,0x0` → 0x0E4388 `b.f.0x0
  →0x8E42E4` (ранний выход в эпилог) либо QUERY-путь 0x0E438C+
  (достройка completion) → СОБСТВЕННЫЙ эпилог fn (ресторы r17-r23,
  поп 0xf8, внешний [R+4]) — всё, что пыталась синтезировать реплика
  v5k, теперь словами самой fn — **сток-completion**.  r1 остаётся
  R−0xf8 (как при любом возврате FN_A; попает ТЕЛО).
- Стаб (14 слов; W_FAST `jump FN_A` ПОСЛЕДНИМ, w13 = 0x38d784,
  0x95F80078 live-form ×0): префикс w0-w8 == v5k byte-exact кроме
  imm w5 +18→+8 (0xA40A0008 сток ×74 — лучший счёт ретаргета
  префикса в линейке); w9 = `addi r11,r1,0xac`; w10/w11 сбор r3;
  w12 = `ret.r zero,r8,r11` (0xFD005825, сток ×3, rs=8 no-link) —
  ЕДИНСТВЕННАЯ передача.  **РЕПЛИКА УДАЛЕНА**: нет fn-exit слов, нет
  ресторов, НЕТ ПОПА — НОЛЬ записей в память кроме CR-эхо w6/w8,
  НОЛЬ записей r1 вообще, r17-r23 НЕ тронуты (реставрирует
  собственный эпилог fn), после w12 из зоны стаба НЕ исполняется
  НИЧЕГО (гипотеза фриза (ii) — fetch со страницы зоны стаба —
  невозможна).  НОЛЬ b_t; r4/r5/r6/r14-r16 не тронуты.
- Payload (`payload.payload_v5l`, 4 слова == v5k, кадр 36B ==
  v5k-TRIG byte-exact): p0 set3-rs-zero-lo + p1 set2-hi →
  r12=0x53324F4B (live-проверено); p2 `st.d r12,zero,0x2388` = S2OK;
  p3 выход в тело fn через r3.  **ОДИН фиксированный кадр для ВСЕХ
  SP-баз** (выход — абсолютный resume, тоже базо-независимый);
  fallthrough — прежний 36B lineage.
- Sim-контракты: exit = 0x8E4380 ТОЧНО (не внутренний остаток
  0x8E435C livelock-класса, не внешний [R+4] реплика-класса — сиды
  игнорируются); r1 НЕ попается; r17-r23 НЕ реставрируются; r4=0
  не тронут; sweep 16 SP-баз фиксированными словами — везде
  EXIT_8E4380 + S2OK; TRIG байты гоняют путь на нескольких базах;
  STUB_ZONE_TARGET-класс отсутствует на всех путях.
- Дифф v5k→v5l (ассертится): −10 слов реплики − 4 позиционных imm
  (w5 0xA40A0012→0xA40A0008; w10 0x2003D784→0x20034380; w11
  0x246300B8→0x2463008E; W_FAST 0x95F8006E→0x95F80078); всё
  прочее идентично.
- Интерпретация: чистый completion + 0x2388=0x53324F4B ⇒ **FULL C1**
  (исполнение + сток-completion — полная цель S2); wedge/иное + S2OK
  ⇒ зависимость тела от эффектов FN_A (диагностируемо; S2OK уже в
  банке); чисто + нет S2OK ⇒ регрессия сборки (CR назовёт: 0x53325F7B
  = OR+остаток — сборка сломана; иное = доставка p0).
- md5 v5l: `6510fdb0f8247ac781a354e26056f013`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked, rebuild детерминирован.
  Слово-таблицы + decode + цензус + sim-контракты — журнал task-34.
  Burn/live — координатор (off-line задача).

## v5m (mode "B" — output-mailbox WRITE-POST; task-02 s2b)

- Основание (Task 1 RE3, task-1-report): m2 — ранжированный выбор
  MARSHAL_MECH: ОДИН вызов сток-обёртки транспорта
  `0x18064c(r4=0, r5=obj, r6=C, r7=buf)` = X1=0x18a668(obj,C) → 0x2ae98
  → 0x2a154: DMA 0x40 байт buf → хост X1, байт-экзактно.  r4=0 —
  dir==0 WRITE-POST субпуть (декод 0x180674-0x180690); obj=r22
  (callee-saved, только читаем); C=[r1+0xac]|0xff (ключ сток-F_SYN
  FETCH; на TRIG-кадре = p0|0xff = 0x200C4FFF); buf=r1+0xb0 =
  input[0x18..0x58) = p1..p3 + стек-хвост — НОЛЬ новых записей в
  FW-RAM (постятся собственные байты TRIG-кадра).
- Стаб (**21 слово**, mode "B", версия 18, alias `v5m`; W_FAST
  ПОСЛЕДНИМ w20 = 0x38d7a0, слово 0x95F80071 — байт-экзакт W_FAST
  v5cA, тот же адрес): префикс w0-w8 == v5l byte-exact кроме imm w5
  +8→+15 (0xA40A000F сток ×19) → m2-блок w9-w15 (`00040000` ×9351
  (сам сток @0x0e4374) / `FEC5B008` ×3226 (сам сток @0x0e4378) /
  `642600AE` ×5 / **GOLDEN `30C600FF` ×47 — immediate-OR (op 0x0C)
  извлечён из блоба (прецедент T3-S2; энкодера в enc.py нет, слово
  инлайн)** / `002700B0` ×5 / call site-imm `94F7CBB1` / рессид
  r4=0) → w16-w19 == v5l w9-w12 byte-exact (сдвиг +7: payload-ptr,
  сбор r3 = RESUME_LIVE 0x008E4380, передача `FD005825` no-link).
  Вызов — РЕАЛЬНЫЙ call (линкует csr0xbc, клобберит caller-saved):
  r3/r11 строятся ПОСЛЕ m2-блока (w15 восстанавливает r4=0 — тело
  маршалит r4 на resume; «r3/r11 после m2» — класс-нота Task 1).
  Грязный csr0xbc после вызова безопасен: путь после resume пишет
  csr0xbc своим `call 0x0e4424' @0x0e43b8 до любого чтения (скан
  блоба; ранний-выход читает только внешний [R+4]).
- Payload/кадры: БЕЗ ИЗМЕНЕНИЙ v5l (4 слова; TRIG 36B байт-экзакт ==
  v5l-кадр — режим B живёт только в сожжённом стабе).  POST идёт ДО
  исполнения payload ⇒ экфилятся ИСХОДНЫЕ TRIG-байты (S2OK идёт в CR,
  не в buf).  TRIG:
  `0932000000000000000000000004000000005332200c4f4b258c53326c04638afd001825`;
  fallthrough — прежний 36B lineage (`09320000`+`00`×32).
- Sim-контракты: m2-вызов ТОЛЬКО на magic-пути, подпись точная
  (r4=0, r5=r22, r6=mem[r1+0xac]|0xff, r7=r1+0xb0); POST до payload;
  r1 НЕ пишется вообще (кадр калли балансирован; попает тело);
  ноль записей вне CR-эхо; выход EXIT_8E4380 на всех 16 SP-базах;
  модель клобберит r3/r4/r11 мусором НА вызове — слова w15-w18
  перестраивают их (re-establish дисциплина load-bearing).
- Live-гейты Task 3 (риски Task 1): (а) X1-miss — POST в мусорный
  хост-адрес: пилот = маркер + скан буферов тула, маркер вне тула ⇒
  STOP без повторов; (б) гипотеза X1 = блок самой команды (exfil в
  буфер тула) живо не доказана; (в) вызовы из детура — новый
  поведенческий класс: шагать echo-first.  Инструмент
  `/root/s2-trigger` ЗАПАТЧЕН (task-02): в лог завершения добавлен
  `outbox len=N hex=…` (полный hexdump output-mailbox; md5
  03b904d9… → 1a84b92503185856e47bbbcab8a50dfd; протокол приоритетен,
  адаптирован инструмент — прецедент task-06).
- md5 v5m: `e71bfa9ccabb718626ae16c271b023ec`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked, rebuild детерминирован
  (бит-в-бит).  Слово-таблица + decode + цензус + sim — журнал
  task-02 s2b.  Burn/live — Task 3 (GO владельца).

## v5n (mode "B" — m2′ X1-from-p0, DIRECT POST; s2b2)

- Основание (plan-2 s2b2, Task-1 CENSUS): вместо сток-обёртки v5m
  `0x18064c` — ручная сборка X1 + ПРЯМОЙ call в транспорт `0x2ae98`
  (r4=X1, r5=buf, r6=status=0).  X1 считается из СОБСТВЕННОГО p0
  TRIG-кадра (НОЛЬ новых данных): `ld.d r4,r1,0xac` (zext32(p0)=w)
  → `shl64.i r4,r4,6` → `set1 r4,r4,0x8fc0` ⇒ X1 = 0x8FC010A2E400
  (для w=0x428B90; 64B-выравнивание by construction, X1&0x3F=0).
  64-битные регистры (slaspec size=8: set1 = биты 32-47, set3 = 0-15).
- Стаб (**22 слова**, mode "B", версия 19, alias `v5n`; W_FAST
  ПОСЛЕДНИМ w21 = 0x38d7a4, слово 0x95F80070 — байт-экзакт W_FAST
  v5h, тот же адрес): префикс w0-w8 == v5m byte-exact кроме imm w5
  +15→+16 (0xA40A0010 сток ×22) → m2′-блок w9-w14 (`642400AE` ×20 /
  `FC843081` ×253 / `1C848FC0` ×3 / `002500B0` ×6 / `00060000` ×2317 /
  call site-imm `94F275C4` ×0 — call-класс, site-imm уникален) →
  w15 рессид r4=0 (`00040000` ×9351) → w16 сборка r12 `200C4F4B` ×0
  (== v5m PAYLOAD p0 — live-доказанное S2OK-lo слово, ПЕРЕНОС в зону:
  w2 загрузил frame-magic 0x5332 в r12, без пересборки p1 держал бы
  0x5332 в LO-половине ⇒ CR 0x2388 = 0x53325332; call r12 НЕ клобберит
  — T1 G-a) → w17 payload-ptr, w18/w19 сборка r3 = RESUME_LIVE
  0x008E4380 (== v5m w17/w18, lo-first OR-safe пара), w20 передача
  `FD005825` no-link.  Бюджет 22/34.  Новые в зоне слова — ТОЛЬКО
  w14/w16 (остальные — stock/lineage).
- Payload/кадры: p0 = w (DATA; декодируется в безобидный addi —
  P0_SAFE) + p1..p3 маркеры v5m verbatim; передача исполняет p0..p3
  in-place, выход — call-site resume 0x8E4380 (тело достраивает
  сток-completion).  TRIG:
  `093200000000000000000000000400000000533200428b90258c53326c04638afd001825`;
  fallthrough — прежний 36B lineage (`09320000`+`00`×32).
- Sim-контракты (64-битные регистры): call ТОЛЬКО на magic-пути,
  подпись точная (r4=X1, r5=r1+0xb0, r6=0); call клобберит
  caller-saved {r3,r4,r5,r7-r11}, НЕ пишет r12/r1; post-call
  пересборка load-bearing (отрицательный контроль: w16 нейтрализован
  ⇒ CR 0x2388 = 0x53325332, тест ловит); EXIT_8E4380 на всех
  16 SP-базах.
- Дифф против v5m (image-level): ровно {w5} ∪ {w9-w14} ∪ {w16-w21}
  (w15 идентичен); детур и GUID-секции не меняются.
- md5 v5n: `b91848dc96354b1003fc29397aa39eba`; verify --deep PASS,
  mstflint bootable PASS, GUID'ы карты baked, rebuild детерминирован
  (бит-в-бит).  Слово-таблица + цензус + sim — журнал
  2026-10-02-irisc-s2b2-v5n-task-02.  Burn/live — GO владельца.

## v5o (mode "B" — m2′ in_mb0-кандидат, лестница A.2 шаг 1; s2b2 план-3)

- Основание (план-3 s2b2, лестница A.2/Б.2): v5n-кандидат out_mb0
  потреблён (FAIL — Б.2), следующий кандидат = **in_mb0**: w = 0x428B80
  (IOVA in_mb0 = 0x10A2E000, 2 сессии) → X1 = **0x8FC010A2E000**
  (w<<6; 64B-выравнивание by construction, X1&0x3F=0).
- Стаб: **== v5n byte-exact** (22 слова, версия 20, alias `v5o`):
  m2′-блок w-независим — w9 `ld.d r4,r1,0xac` читает p0 (= w) из host
  TRIG-кадра в РАНТАЙМЕ; w в стабе на момент сборки отсутствует
  (дизайн-факт 1 плана). Идентичность — **тестируемый контракт**:
  `built(20) == built(19)` + md5-золото (TestS2BuildV5O); v5n
  drift-check'и блока работают без изменений.
- Payload/кадры: p0 = w = 0x428B80 (P0_SAFE: `addi r2,r2,0x-7480` —
  безвредный r2-клоббер) + p1..p3 маркеры v5m verbatim; TRIG:
  `093200000000000000000000000400000000533200428b80258c53326c04638afd001825`;
  fallthrough — прежний 36B lineage (`09320000`+`00`×32).
- BUF_LAYOUT v5o (цель in_mb0; cross-check по G-c-дампу — журнал
  task-01 Step 2): без POST — staging frame[0x10..0x24) @
  [0x00..0x14), QUERY-серия с 0x14 (`10009000`@0x14, stride 8,
  idx 0xa..0x46 @0x1c..0x1fc), нули @0x200..0x23c, tail
  `000078c2`@0x23c; успех (прогноз) — маркер
  `258c5332 6c04638a fd001825` @ in_mb0[0x00..0x0C) (окно вне
  QUERY-покрытия → доживает до дампа); контроль — out_mb0-класс
  (POST не там: [0x00..0x28)=0, stale @0x2a, QUERY @0x44..0x1fc).
- CR-карта: 0x23f0 (S0 = 0xbadc0001), 0x2380 (MAGIC16-эхо 0x5332),
   0x2384 (N-эхо 4), 0x2388 (S2OK 0x53324F4B), 0x238C/0x2390 (= 0);
   бейслайн после power-cycle (no-burn; v5o==v5n уже во флэше) — нули
   (Б.6-4; T2-rework, owner-решение 2026-10-04).
- Sim-контракты: зеркало v5n-модели subclass'ом (TestS2StubV5OSim) —
  модель version-agnostic (стаб byte-exact v5n), меняются только
  frame-зависимые ожидания (X1 = 0x8FC010A2E000, p0 = 0x428B80).
- md5 v5o: `b91848dc96354b1003fc29397aa39eba` — **== md5 v5n**
  (идентичность, дизайн-факт 1); verify --deep PASS, mstflint
  bootable PASS, GUID'ы карты baked, rebuild детерминирован
  (бит-в-бит).  Слово-таблица + BUF_LAYOUT cross-check + sim — журнал
   2026-10-03-irisc-s2b2-v5o-task-01.  Power-cycle (no-burn) + live —
   Task 2/3 (GO владельца).

## База

- `build/4030-cda-patched3.bin`, md5 `082e9678b54d0512cec2f155037e82b7`
  (S0 boot-marker уже внутри: инъекция @0x1d594 → шеллкод @0x38d730,
  CR 0x23f0 = `0xbadc0001`).
- Проверенные слова базы (ассерты билдера): 0x0e437c=`0x9402a57a`
  (stock `call 0x18d964`), 0x1d594=`0x940dc067`, 0x18d964=`0x480300bc`.

## Зоны (доктрина v3-fail, ассертится билдером)

| Диапазон | Статус | Использование |
|---|---|---|
| 0x38d730–0x38d747 | S0-шеллкод | сохранён (пословный контроль до/после) |
| 0x38d748–0x38d74f | запретный вырез | нули, не трогать |
| **0x38d750–0x38d7d8** | **слот S2-стаба** | **34 слова, v1 занимает все 34** |
| 0x38d7d8–0x38dbe8 | фатальная зона (≥0x38d7dc доказано) | нули, не трогать |

Дифф против базы: 1 слово @0x0e437c (`call 0x38d750` = `0x940aa4f5`) +
34 слова стаба + per-line clcrc (4 линии: 0x0e4340, 0x38d740, 0x38d780,
0x38d7c0) + ITOC 0x03 entry/section CRC (`mlxfwutil.patch_sections`).

## Стаб (mode A, 34 слова, декод — журнал task-04; compare-слово — v2 выше)

- Вход: ra=0x0e4380 (csr0xbc), args r4–r10 стоковые; r1 = фрейм fn 0x0e4250.
- Clobber: только {r3, r11, r12, r13} + r4/r5/r6 (сохранение/рематериализация);
  r14+ не трогаются; csr_w не используется.
- Фрейм стаба 0x40 (T1 STUB_FRAME_OK): [r1+0x00]=ra; [r1+0x18]=r6 (st.d/ld.w);
  [r1+0x20..0x34)=payload (N≤5 слов — доказанный FIT); [r1+0x34..0x40)=result-буфер.
- Восстановление: r3=ra (слот), r4=0 (`addi r4,zero,0` — сток @0x0e4374),
  r5=obj (`or r5,r22,r22` — сток @0x0e4378), r6 (st.d/ld.w), r1 pop, tail-jump FN_A.
- Resume-PC для payload: r3 = 0x00b8d7c0 (live = file 0x38d7c0 + 0x800000).

## CR-карта S2

| Слот | Пишет | Значение |
|---|---|---|
| 0x23f0 | S0-шеллкод (база) | `0xbadc0001` boot-liveness |
| 0x2380 | стаб (эхо) | сравненное слово (v4: DISCRIM32 на магии; v2: MAGIC) |
| 0x2384 | стаб (эхо) | N |
| 0x2388 | стаб v5cB (счётчик итераций) / payload (маркер T5: v4 marker-lite; v5j p2: S2OK; v5k/v5l p2: S2OK exact) | v5cB: 4/3/2/1 по итерациям; v4/v5j/v5k/v5l: S2OK=0x53324F4B (гейт G5'/G5; v5j/v5k/v5l — C1-сигнал; v5k/v5l сборка rs=zero — точна при OR/insert семантиках; live v5j видел 0x53325F7B = OR-остаток; live v5k = 0x53324F4B EXACT) |
| 0x238c | стаб v5cA/v5cB/v5d/v5e/v5f/v5g/v5h/v5i (маркеры стадий) / payload (маркер v2) | v5cA: M0-M2=1-3; v5cB: M1/M2=2/3 (фриз → группа); v5d: M=7 «copy done»; v5e/v5f: shared-TAIL эскалации N=2→2 / N=3→3 / N=4→0 / N=1→0 (фриз@N=k называет блок); v5g/v5h: всегда 0 (r13 исчерпан; N — только порядком протокола); v5i: N=r13-as-is (цикла нет; фриз ⇒ 0 — fresh baseline); v5j rev.2/v5k/v5l: НЕ пишется (эхо посадки снято — S2OK самовалидирует; на magic-пути 0); v2: r5 |
| 0x2390–0x2500 | резерв payload | MAPPED-ран (PC3 §B) |

## Конвенция payload (ограничения v1)

- Возврат ТОЛЬКО `ret.r zero,zero,r3` (r3 установлен стабом); `call` в payload
  запрещён — csr0xbc должен держать 0x0e4380 к моменту tail-jump FN_A.
- Callee-saved r17–r23 payload обязан сохранять (T1 CALLEE_SAVED).
- N≤5 слов (IN_SIZE 0x24 − 16B заголовок); N=0 копирует 1 слово (do-while);
  N>5 наезжает на result-буфер (RES_OFF=0x34) — расширение только после T6.

## Генератор payload (Task 5)

`payload.py`: `marker(r5, r6)` — 5 слов ровно (R7): `set2 r7,0x5332;
set3 r7,r7,0x4f4b; st.d r7,r0,0x2388; st.d r5,r0,0x238c; ret.r zero,zero,r3`
(S2OK=0x53324F4B → 0x2388, r5 → 0x238C; r6-write снят по бюджету, аргумент
принимается/валидируется, значением не пользуется). `input_block(words,
r5, r6) -> bytes` — BE-слова `[MAGIC, N, r5, r6, *words]` c fail-loud
ассертами (R8): N∈[1..5], words/r5/r6 — u32. `PAYLOAD_MAX = IN_SIZE-16 = 20`
(IN_SIZE=0x24 strictly-clean, T2); при N=5 input-блок = 36 байт = IN_SIZE.
Декод-слова и кросс-чек против IN_LAYOUT_MAP — журнал task-05.

## Как запускать

```sh
python3 scripts/s2/build_s2.py            # default: v4 → /tmp/opencode/s2/4030-cda-s2-v4.bin + md5
python3 scripts/s2/build_s2.py OUT 2      # v2 (MAGIC@0 filter, selector-fix)
python3 scripts/s2/build_s2.py OUT 5      # v5a (echo-probe)
python3 scripts/s2/build_s2.py OUT 6      # v5b (фильтр + gauntlet)
python3 scripts/s2/build_s2.py OUT 7      # v5c-A (frame-only probe, M0-M2)
python3 scripts/s2/build_s2.py OUT 8      # v5c-B (full write-path, M1/M2 + counter)
python3 scripts/s2/build_s2.py OUT 9      # v5d (stock-conformance copy path)
python3 scripts/s2/build_s2.py OUT 10     # v5e (escalation N-gates bisection)
python3 scripts/s2/build_s2.py OUT 11     # v5f (skip-idiom gates)
python3 scripts/s2/build_s2.py OUT 12     # v5g (linear fork-test)
python3 scripts/s2/build_s2.py OUT 13     # v5h (no-save linear)
python3 scripts/s2/build_s2.py OUT 14     # v5i (neutral-write discriminator)
python3 scripts/s2/build_s2.py OUT 15     # v5j (exec-from-input C1 attempt)
python3 scripts/s2/build_s2.py OUT 16     # v5k (exact S2OK + epilogue replica)
python3 scripts/s2/build_s2.py OUT 17     # v5l (call-site resume exit — ФИНАЛ S2, FULL C1)
python3 scripts/s2/build_s2.py OUT 18     # v5m (mode B: output-mailbox WRITE-POST; s2b)
python3 scripts/s2/build_s2.py OUT 19     # v5n (mode B: m2' X1-from-p0, DIRECT POST; s2b2)
python3 scripts/s2/build_s2.py OUT 20     # v5o (mode B: m2' in_mb0-кандидат; s2b2 план-3)
python3 mlxfwutil.py verify --deep /tmp/opencode/s2/4030-cda-s2-v4.bin
python3 -m pytest tests/test_s2_build.py tests/test_s2_payload.py -q
```

Выходы — `/tmp/opencode/s2/` (в репо не кладутся). Burn — Task 7 (docs/850-howto/100-cross-flash-ops §6,
флаги из ledger D3 S1, GO владельца).
