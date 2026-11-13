# cx4lx-detour dump-semifabricate: builder + string scanner (D1/D2)

Скрипты в этой директории собирают «dump-образ» для CX-4 Lx 14.32.1900:
сток-base + runtime-хук, стаб которого читает заданный список слов FW RAM
и эмитит их ОДНИМ iTrace-событием (emitN, парамы r5.. = значения слов,
рендерит их форматная строка-маркер). Канон метода — docs/250-re/120-irisc/050-cx4lx-dump-cycle.md, отчёты
D1/D2. Burn-рецепт — в handoff-разделe отчёта D2 и docs/850-howto/100-cross-flash-ops §6.

## build_dump_d1.py (пресет D1, наша карта)

Дефолты: GCA-сток refs + guides карты bazzite 04:00.0, H0-хук, список
[w2,w3, битсет×4, гейт 0xE2B4], строка 0x00ada612 (1 %x — виден только
первый парам; урок D1). Live-доказан (C-D1: 1019/1019 w2==маска).

## build_dump_d2.py (пресет D2, сессия-потребитель)

Дефолты = пресет потребителя sfp28: base `build/c1-00-ri.bin` (их ri,
md5-гейт dacbcf0e…), адреса `0x8,0x0D600C,0x0D6010,0x0D6014,0x0D6018,
0xE2B4,0xD5DC`, строка 0x00aeb83b (7×%x — видны ВСЕ парамы), emit7,
guides skip (их ri уже несёт DEV_INFO/MFG_INFO — гейтится), link r17.

Параметры:

- `--base/--base-md5` — их ri и ожидаемый md5 (`none` = снять md5-гейт,
  структурные гейты решают);
- `--gca-ref` — GCA-сток для byte-compare MAIN_CODE (вердикт ACA↔GCA;
  при расхождении — дифф-отчёт, но НЕ аборт: expected_before решает);
- `--trigger H0|H6` — H0: сайт 0xd3850 в register-хэндлере (триггер =
  любая register-команда; live-доказан); H6: сайт 0x1b9da4 в трейс-точке
  init_ib_an_fsm, класс 0x40 уровень 1 (триггер = сам AN-loop ~0.4 c;
  live НЕ валидирован — fallback H0);
- `--guides skip|run` — skip: гейтится наличие DEV_INFO(0xE1)+MFG_INFO
  (0xE0) и совпадение GUID/MAC с `--expect-guid/--expect-mac`, образ =
  step1 (без переписывания device-data); run: как D1 (`--guid/--mac`);
- `--addrs` — слова через запятую, ПОРЯДОК = ПОРЯДОК ПАРАМОВ r5, r6, …;
- `--string-rt` — rt мёртвой db0-строки (число %-токенов ≥ парамов;
  %x/%d/%u валидны, %s и пр. — нет); проверяется мёртвость на ЭТОЙ базе;
- `--emit {1,2,3,4,7}` — обёртка (парам-слоты), `--link-reg` — держатель
  линка (callee-saved, r17 — верифицирован для обоих триггеров);
- `--build-id-text/--build-id-date` — ini build-ID (D2b, скилл
  mellanox-fw-build R1/R2): строка `; mlxini cx4lx-dump-<trig> (<дата>,
  <base md5>): <суть>` сразу после `;; Mellanox Technologies LTD`; бюджет
  0x30 = e.size−32, при превышении трим только `;;`-комментариев
  (баннер/`;;[PS_INFO]`/длинные `;;;;` >60 B; key=value и навигационные
  `;;;;` не трогаются — фильтр-гейты); не влезло — СТОП без
  `--repack-force`; гейт `mstflint dc | head` = маркер первая
  содержательная строка;
- `--out` — по умолчанию `build/cx4lx-dump-d2-<trig>.bin`.

Как добавлять адреса: дописать в `--addrs` (4-выравнив; ≤ слотов emit;
порядок = порядок вывода). Пакер сам выберет форму: `ld.i` для адресов
≤0x2000 (зона control-блока: w2/w3 — форма читалки GATE), offset-batch
`ld.d` от последней материализованной базы (±0x1FF8), иначе
set2/set3+ld.d. Каждый стаб-слово decode-верифицируется; бюджет кейва
24 слова (сейчас 18/24; при нехватке — уменьшить список или emit ниже).

## scan_dead_strings.py

Скан db0 (dc [0x2d6900,0x31b300)) на мёртвые формат-строки: NUL-сегменты
+ суффиксы (rt в середину строки), валидные токены %x/%X/%d/%u/%i,
включая precision (%.4x); мёртвость = 0 addi/addi.hi-загрузчиков rt +
0 raw-слов в MAIN_CODE. `--base` (по умолчанию GCA-сток; чужая база —
результаты локальны для неё), `--min-tokens`. Лог:
`build/cx4lx-d2-dead-strings.log`. Выбор D2: rt 0x00aeb83b (7×%x).
