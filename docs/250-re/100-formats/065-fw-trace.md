# 065. FW-трассировка Mellanox (iTrace / mstfwtrace): семантика и ограничения

> Источник: (а) разбор OSS mstflint 4.37.0-1.1 (`refs/src/mstflint`, tag
> `v4.37.0-1.1`, SHA `1b8ac4b5`; `tracers/fwtrace/` — mstfwtrace.py, 31
> класс, setItrace) + mainline-драйвер mlx5 (`diag/fw_tracer.c`); (б)
> live-пробы root-mellanox, ConnectX-5 Ex 15b3:1019, BDF 0000:81:00.0/.1,
> жертвенная iRISC (2026-10-08/09); (в) RE v5q/v5r-образов 16.35.4030
> (strings DB + call-sites, 1861 сайт). Журналы:
> `docs/superpowers/journal/2026-10-08-mstfwtrace-probe.md`,
> `2026-10-08-mstfwtrace-followup-task-02.md` (RE классов),
> `2026-10-09-itrace-flr-mask-experiment.md`,
> `2026-10-09-irisc-itrace-v5r-nodata.md`,
> `2026-10-09-irisc-itrace-l0-trace-task-0{1,2,3}.md`.
> Рабочий рецепт трассы (how-to) — `docs/850-howto/150-fw-trace.md`.

Связи: trace-машина CX-4 Lx (14.32) и эмиссия из детур-шеллкода —
`docs/250-re/120-irisc/035-cx4lx-trace.md`, runtime-хук — `…/040-cx4lx-hook.md`;
детуры/инъекции iRISC — `…/025-boot-injection.md`; Ghidra/ISA —
`…/010-isa.md`; S3-trigger (проба 0x0932, T2b, H4) — план
`docs/superpowers/plans/2026-10-05-irisc-s3-trigger-probe.md`; live-операции
и FNP — `docs/850-howto/100-cross-flash-ops.md`; tooling mstfwtrace AppImage
— commit `2d409b9`, `scripts/mft-stage.sh`.

## 1. Что это (архитектура)

iTrace — встроенный трассер iRISC-FW: события пишутся в DMA-ринг (до 512 KB,
блоки 32×8B), из которого читает драйвер (mlx5, `diag/fw_tracer.c`) и выдаёт
ftrace-событие `mlx5/mlx5_fw` (format: `dev_name [0x<fw-ts>] <lost>
[0x<event_id>] <msg>`). Строки сообщений — из strings DB (таблица
rt-адрес → форматная строка; параметры — word'ы после первого).

- **mstfwtrace — обёртка, не прямой доступ к трассе**: ставит ITACE-маску и
  уровень (ICMD-команда) и tail'ит ftrace-вывод драйвера. Сам DMA-ринг
  событий читает ТОЛЬКО ядренный драйвер mlx5 (`diag/fw_tracer.c`:
  ownership + MTRC_CONF/CTRL + EQ → парсинг 32×8B → tracepoint);
  user-space доступ к рингу не имеет. Даже «secure-режим» mstflint
  (SecureFwTrace) tail'ит тот же ftrace-файл — user-space читателя ринга
  в mstflint нет.
- **Data-path: трасса работает, даже когда одна PF отвязана / на VFIO.**
  Ринг живёт в **RAM хоста**: mlx5_core owner-функции выделяет его
  DMA-аллокацией и передаёт адрес FW (MTRC-регистр). Записи **пишет сам FW
  (iRISC) по DMA**; драйвер читает ринг обычным чтением host-памяти
  (memcpy) — **PCI-транзакций к карте по data-path нет вообще**. Контроль
  (SET_ITRACE маска/уровень, MTRC_CAP/CONF/CTRL) — ICMD на owner-функции.
  FW — один экземпляр на карту (один iRISC на оба PF); iTrace-контекст
  (mask/level в word 2/3 local RAM, адрес ринга) — **device-level**, не
  function-level: ни FLR f0, ни VFIO-бинд f0 не влияют на генерацию и
  чтение (эксперимент FLR/маска, 2026-10-09). Единственное требование:
  **owner-функция трассера остаётся привязана к mlx5_core** — это и
  читатель ринга, и owner трассера.
- Включается в два шага: (1) драйвер берёт ownership трассера при device-up
  (сам; user-space может только GET MTRC_CAP; GET MTRC_CONF/MTRC_CTRL даёт
  ICMD error), (2) ftrace-событие включают вручную (`echo 1 >
  /sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable`).
- Ядренного драйвера (Fedora, mainline) достаточно; OFED не нужен
  (гипотеза «OFED-only» опровергнута live).

## 2. Наш стек (root-mellanox, 81:00.0/.1)

- MTRC_CAP (v5r/v5q): trace_to_memory=1, trc_ver=1, num_string_db=2
  (db0 0x4f700 @ rt 0x00b46180; db1 0x3800 @ rt 0x0103b200),
  log_max_trace_buffer_size=0x13 (512 KB).
- Quirks (live): GET MTRC_CAP всегда отчитывает `trace_owner=0`; GET
  MTRC_CONF/MTRC_CTRL из user-space → ICMD error (0x6C64FE/0xB63790);
  **ownership эксклюзивна**: owner-функция **недетерминированна per boot**
  (эра 10-08 — f1 = 81:00.1; boot 2026-10-09 16:56 — f0 = 81:00.0).
  Трасса = `mstfwtrace -d <текущий owner>`, хотя трафик/проба — на 81:00.0.
  Привязанный non-owner mlx5 сам забирает ownership на release-EQ; rebind
  owner-функции → переворот ownership. **Перед трассой определять owner**
  (dmesg `FWTracer` после rebind, либо BDF в raw ftrace-буфере) — хвост по
  не-owner BDF = 0 событий без какой-либо ошибки.
- FW карты — 16.35.4030; v5r = сток (ri body byte-identical
  `4030-cda-s2-v5r.bin`; 48 байт diff vs v5q), v5q = детур-образ.
  **Карта на v5r — текущее состояние** (после L0-цикла 2026-10-09; история
  бёрнов v5q→v5r — журналы L0-цикла).

## 3. Маска и уровень — семантика (verified RE, v5q)

- `-m` — бит-маска классов, `-l` — уровень; **строго парой** (mstfwtrace
  требует оба). Механизм: `cmdif.setItrace(mask, level)` → ICMD opcode
  0xf003 (SET_ITRACE) → mask/level в local RAM word 2/3.
- **`-l N` = «события уровня >= N»** (не «<= N»): собственный уровень
  события (0..7 per trace-site) сравнивается с stored level (word 3)
  borrow-чеком.
- **События уровня >= 2 обходят class-маску** (гейт `b.t` на `level > 1`).
  **Важно: `-l 2` — НЕ «всё»**: фильтрует ВСЕ события L0/L1 (1212 из 1413
  сайтов, включая command-path ICMD) и пропускает только L>=2 всех классов
  (172 сайта) — узкий кросс-классовый поток. «Всё» (все классы, все
  уровни) = `-m 0xffffffff -l 0` — но это флуд (см. §6).
- События уровня 0/1 проходят полный mask&class-чек.
- Strings DB: db0 (4118 строк) = сама code-секция (MAIN_CODE de-clcrc;
  MTRC_CAP: base rt 0x00b46180 size 0x4f700 = file [0x346180, 0x395880));
  db1 (строка `IRON populate_local_dbase`) **не в образе** — ROM.

## 4. Классы (маска ↔ подсистема)

Таблица mstfwtrace 4.37.0 (31 имя) **не совпадает полностью с v5q-FW**
(RE 1861 call-site; «подсистема» — по строкам сайтов):

- **command-path (mstreg/mstflint-трафик) = класс ICMD (26)** —
  live-verified (контроль: 5/5 маркеров → 5 icmd,
  `icmd_generic_reg_access`, register_id=0x9040). НЕ CMD_IF/MANAGEMENT/
  CMD_DRIVER — эти классы на mstreg-трафике молчат (run1/run2 = 0 событий).
- **Бит 31 = NODNIC — класса в таблице mstfwtrace НЕТ** (25 сайтов:
  nodnic_cmd_interpreter, isr_nodnic_*); выбирается только integer-маской
  `-m 0x80000000`.
- Бит 16 «I2C» по строкам = QoS-планирование + SMBus (имя неточно).
- Бит 8 (LIBFHI) — 0 сайтов в v5q.
- Остальные 27 имён: подсистемы по строкам в таблице RE (verified по коду;
  имя — таблица mstfwtrace) — журнал followup-task-02 §5.

Для трассировки детуров:

- cmd-dispatch-регион [0x0e4250, 0x0e4424): один живой сайт 0x0e4410 =
  завершение query_flow_table, класс **CMD_IF (бит 5), L0**;
- FN_A (ft_test_and_update, 0x18d964): 2 сайта, error-пути, **STEERING
  (бит 24), L0** (на v5q stub их обходит — дискриминирующая пара v5r/v5q);
- **точка детура 0x0e437c и stub 0x38d750 — trace-сайтов НЕТ**: детур сам
  по себе трассой не виден, виден только command-path вокруг.

## 5. Проба 0x0932 под трассой — итог

Проба 0x0932 сама icmd-события не даёт (её трассируемые сайты — классы
CMD_IF/STEERING, L0); command-path пробы трассируется маской
`0x5000020 -l 0` (CMD_IF|STEERING + ICMD для маркер-верификации) —
FN_A-дискриминация v5r/v5q подтверждена live: на v5r пойманы W6 `0x18da3c`
(= RE-прогноз дословно) и `cmdif_driver cmd_failure opcode=0x0932`, на v5q
stub обходит FN_A (DONE + S2OK вместо W6). H4-след (icmc-miss @POST-va,
v5q-only) — открыт (событие потеряно во флуде 0x9043). Детали — журналы
L0-цикла 2026-10-09 (`2026-10-08-mstfwtrace-followup-task-03.md`,
`2026-10-09-irisc-itrace-l0-trace-task-0{1,2,3}.md`).

## 6. Ограничения

- Shellcode детура для iTrace невидим: свои записи в трасс-ринг из
  shellcode — отдельный проект (формат записи 32×8B + локация буфера в
  контексте детура; CORE-запись @ 0x1b430).
- `event_id` нестабилен (0xb0..0xba и т.п. — не класс, а порядковый/статусный
  счётчик записи); correlate по строкам и FW-timestamp.
- Ринг 512 KB + lost-флаг в событии; флуд = потеря. Флуд-ловушки: all-classes
  (`-m 0xffffffff`) — залипание ринга; CMD_IF-биты с `-l 0` —
  самоусиливающийся флуд 0x9043 (драйвер поллит MTRC при EQ-обработке, site
  0x000c756c, класс CMD_IF L0; фильтруется `-l 1`). Анти-флуд-схемы —
  рецепт `docs/850-howto/150-fw-trace.md`.
- Только owner-функция; owner **недетерминирован per boot** (f1 в эру
  10-08, f0 в boot 2026-10-09 16:56 — определять перед трассой, §2);
  трасса = ftrace-хвост драйвера owner'а.
- setItrace-startup race: маска может не примениться до первого события —
  **верифицировать маркером ДО** (mstreg GET → icmd в логе; маркер-окно
  ≥ 18–20 c, ре-иссуя маркер); FLR/VFIO-окно маску НЕ сбрасывает
  (эксперимент 2026-10-09, подтверждено на v5r — флуд 0x9043 шёл через
  FLR-окно). Количественно: из состояния mask=0 применение маски занимает
  **16–18 с (наблюдено), возможно >30 с**; между ненулевыми масками —
  мгновенно. Механизм задержки — открытый след (кандидаты: инициализация
  ICMD-канала / кеширование маски в local RAM; хэндлер SET_ITRACE — вне
  MAIN_CODE, см. ниже).
- `mstreg ... SET` интерактивный: без `--yes` при stdin EOF → `(y/n) [n]`
  → abort с rc=0, **SET не отправлен** — проверять не по rc, а по эффекту.
- Хэндлер SET_ITRACE (запись mask/level в word 2/3) в MAIN_CODE не найден —
  динамическая сборка/вне MAIN_CODE (граница RE).
