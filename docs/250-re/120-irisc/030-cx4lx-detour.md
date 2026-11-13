# 030. Детур на CX-4 Lx: каркас, геометрия, dispatch, read-каналы

> Источник: отчёты цикла `cx4lx-detour` —
> `docs/superpowers/reports/cx4lx-detour-l{0,1,2,3,4}.md`, журналы
> `docs/superpowers/journal/2026-10-11-cx4lx-detour-l{0,1,2,3,4}-task-01.md`,
> спека `docs/superpowers/specs/2026-10-11-cx4lx-detour-design.md`;
> билдеры/хелперы — `scripts/probes/cx4lx-detour/`. Карта —
> `CARD_CX4LX_BCAT` (bazzite, BDF 04:00.0;
> `docs/050-hardware/100-inventory.md`). Метки L0–L4 = вердикты отчётов
> цикла.
> Связи: конвенции слов (BE, dc↔rt, CR↔RAM↔regspace, clcrc) →
> `005-endian-addressing.md`; ISA-семантики → `010-isa.md`; декодеры →
> `015-decoders.md`; CX-5-канон метода → `025-boot-injection.md`;
> trace-машина 14.32 → `035-cx4lx-trace.md`; runtime-хук v3 →
> `040-cx4lx-hook.md`; boot-окно/cable-path →
> `045-cx4lx-boot-window-cablepath.md`; dump-цикл →
> `050-cx4lx-dump-cycle.md`; рецепт сборка+burn →
> `docs/850-howto/190-irisc-build-burn.md`.

Детур на CX-4 Lx (MT27710, FW 14.32.1900, non-secure): установленный
результат (working PoC, L2/L3):

- **Boot-детур работает**: инъекция `call` в entry MAIN_CODE → 6-словный
  шеллкод пишет маркер `0xbadc0001` в CR 0x23f0 → хост читает его через
  VSEC (`setpci`/sysfs-config). Прочитан 4×/4×, карта здорова (L2).
- **Runtime-хук работает**: подмена call-сайта трассировки в
  register-хэндлере → стаб зовёт сток-emit + свой emit → **наше событие
  видно в ftrace** (`memory_profile = 0xbad`, маска ICMD; 104 шт. = 1:1
  к register-командам окна) (L3) — детали `040-cx4lx-hook.md`.
- **ISA совпадает с CX-5** (новых real-op нет; unknown-профиль тот же),
  но **раскладка отличается** — слепой перенос геометрии невозможен
  (L0/L1) — §3 ниже.
- Сборка/burn — прецеденты и гейты: `scripts/probes/cx4lx-detour/
  build_detour_v{1,2,3}.py`; burn `--no_fw_ctrl` (без FNP!), дуал-банк
  (`docs/850-howto/190-irisc-build-burn.md`).

Метод (детур = впрыскнутый в прошивку собственный iRISC-код: точка входа
подменяется call'ом на пещеру-кейв, код делает своё дело и возвращается
к штатному потоку; каналы результата — CR-маркеры, iTrace-события,
чтение памяти FW) — канон на CX-5: `025-boot-injection.md`.

## 1. Каркас (образ, флеш, burn)

| элемент | значение |
|---|---|
| Базовый образ | `refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-…bin`, md5 `3bd3230b1deae0cf74a08e31d59021d9` (FS3, non-secure) |
| MAIN_CODE | ITOC **0x03**, index 18, flash-addr `0x16d000`, size `0x34e8c0`, clcrc=1 |
| Строки | 68 B = 64 код + 2 zero-pad + 2 LE clcrc (calc_hwcrc seed 0); round-trip обязателен |
| Маппинг raw↔dc | `raw = 0x16d000 + line*68 + within`, `dc = line*64 + within`; live-PC = dc + 0x800000 |
| Флеш | 16 MiB, **дуал-банк**: burn `--no_fw_ctrl` пишет НЕактивный банк и переключает активность; `ri` читает активный банк, `rb` — физику (образ в банке A: физика == логике; в банке B: +0x800000). Общий хвост [0xfa0000..0x1000000) — один экземпляр |
| Burn | `mstflint -d 0000:04:00.0 -i <img> --no_fw_ctrl -y burn` (PSID совпадает — без `-apc`); оба маркера обязательны: `Burning FW image without signatures - OK` + `Restoring signature - OK`. **Ребут между burn'ами, сменившими активацию** — иначе pending-update → erase fail (L3-урок) |
| Артефакты | на bazzite — `/root` (/tmp чистится ребутом); fresh `ri` до burn = откат |
| Карта-эталон | `CARD_CX4LX_BCAT` (MCX4131A, плата BCAT), PSID `MT_2430110027`→`MT_2430110032` (GCA); GUID/MAC — реестр `CARD_CX4LX_BCAT` (`docs/050-hardware/100-inventory.md`) — вшивать при сборке |

Рабочие образы (md5; билдеры — `scripts/probes/cx4lx-detour/` и
`scripts/probes/cx4lx-dumpcycle/`):
v1 `e91cac9c…` (boot-детур+маркер), v2 `045536c7…` (reader-хук,
негатив-артефакт), v3 `a7c277dd…` (boot-детур + iTrace-хук; superseded —
банки перезаписаны dump-циклом), cable `cx4lx-cable-t2-an5.bin` `2e863105…`
(`045` §2), dump `cx4lx-dump-ra3c.bin`
`be857b92dd05b85473f5e02e28c90b1e` / `cx4lx-dump-ra3b.bin`
`3fccc48cdfe06ffe77d1507886cb7140` / ra4b-on
`016db98237705566f824c17f29405b4a` / ra4b-off
`184ea4ef51ca56d37120fa62b1672425` (`050`). **Текущее состояние банков**
(владелец 2026-10-17: не трогать): **A = ra4b-off (АКТИВЕН), B = ra4b-on**;
ra3b перезаписан (бит-воспроизводим билдером) — `050` §3.

## 2. Геометрия boot-детура (L1/L2)

Пролог entry (ITOC param1 → dc 0x7edc; та же форма, что на CX-5 —
`025-boot-injection.md` §2):

```
dc 0x7edc  94fff51b  call 0x5348        ; sp_init (r1 = (cpu&0xf)<<13 + 0x7d1ffc)
dc 0x7ee0  703f07fa  st.d! zero,r1,-0x8 ; stack setup
dc 0x7ee4  94000003  call 0x7ef0        ; main-init — ТОЧКА ИНЪЕКЦИИ (3-я инстр.)
dc 0x7ee8  95000000  jump 0x7ee8        ; self-jump (dead)
dc 0x7eec  95000000  jump 0x7eec        ; self-jump (dead)  [дельта: на CX-5 один]
```

- **Инъекция**: raw 0x1756d0: `94000003` → `940c532f` (`call 0x31cba0`,
  rel24 в signed24). Self-jump'ы — dead-code (xref-тишина + healthy-boot);
  главный call-сайт main-init — сам entry.
- **Cave**: dc `0x31cba0..0x31cc00` (**24 слова**, 0x60 B), raw
  `0x4bb858..0x4bb8b8`, EOF-паддинг последних линий; 0 xref / 0 доступов /
  0 указателей внутрь. **Дельта: all-zero ≥256 B в MAIN_CODE 14.32 НЕ
  СУЩЕСТВУЕТ** (макс 24 сл) — расширяемость ограничена; db0-дыры = живые
  данные, не кейв. Cave ВНЕ db0 → своя строка-маркер для iTrace невозможна.
- **CR-слот (канал результата)**: **CR 0x23f0** (= 4·word 0x8fc) — точный
  CX-5-аналог (`025` §4.3): единственный читатель `ld.i r6,0x8fc` в стабе
  0xd4c8c с compare `0xbadc0ffe` (≠ → «locked», r4=1), 36 call-сайтов —
  все runtime (после инъекции); FW-записей 0 (st.i max 0x858; abs-store
  мимо; csr.w потолок 0x41ffc < 0x423f0). Маркер `0xbadc0001 ≠ 0xbadc0ffe`
  → «locked» == сток → поведение FW идентично. Достижим только
  `st.d`-absolute. Чтение: VSEC (standard cap **0x09**, обход caps от
  0x34), CTRL=base+4 (low16 = space, CR=0x2), ADDR=base+0x10 (poll bit31),
  DATA=base+0x14. Дискриминация mapped: unmapped-слот (напр. 0x223f0) =
  off/4 (0x88fc). Запасной: **0x23f8** (занят runtime-счётчиком с бута —
  эратата B2, `045` §1). ~~0x23ec~~ — занят (extm-mailbox, L4-эратата).
- **Scratch**: r5/r6 — да (write-first в main-init на обеих ветках; r5 ещё
  затирается sp_init). **Live-in только r1, r23** — дельта: r3/r4 на 14.32
  write-first (CX-5-гипотеза «r1/r3/r4/r23» опровергнута для 14.32).

Шеллкод v1 (6 слов @0x31cba0, все decode-верифицированы; прецедент-тест —
`tests/test_irisc_asm.py`):

```
24050000  set2 r5,zero,0x0000     ; r5 = 0
20a523f0  set3 r5,r5,0x23f0       ; r5 = 0x23f0 (CR)
2406badc  set2 r6,zero,0xbadc     ; r6 = 0xbadc0000
20c60001  set3 r6,r6,0x0001       ; r6 = 0xbadc0001
6ca03002  st.d r6,r5,0x0          ; [CR 0x23f0] = маркер
95f3accf  jump 0x7ef0             ; resume main-init
```

Осторожно с `set3` (rs=rd = OR-семантика) — гейт скилла `irisc-asm`.

## 3. ISA-паритет с CX-5 (L0)

Семантики форм — `010-isa.md`, канонический декодер/ассемблер и
strict-профили — `015-decoders.md`; профиль чипа —
`scripts/irisc/profiles/cx4lx.json` (verified_on 14.32.1900-GCA; скилл
`irisc-asm`). Здесь — только факт паритета 14.32 ↔ 16.35:

- Unknown в коде **1.33%/1.09% (strict)** vs 4030 1.28%/1.05%; ядро то же:
  0x36 (3667), 0x0d (3010), 0x33 (1803), 0x34 (1319); NOISE-множество
  идентично; **новых real-op НЕТ** (10 mask-op = strict=0, табличный хвост).
- SHA-256 K-таблица-якорь @dc 0x319850 (64/64 exact) — Rosetta-опора.
- Редкие real-ops 4030 (0x16/0x38/0x1d) на 14.32 ≈0 — версионный хвост.
- Golden round-trip энкод-слов 11/11 (set2/set3/st.d/jump/call + live
  addi/set3/b.t/b.f). Вердикт: гипотеза единой mlx5-кодовой базы (14.32 ↔
  16.35) статик-поддержана; live-подтверждение — сам детур (L2/L3).
- Live-формы, внесённые в профиль cx4lx циклами детура (+3, владелец
  2026-10-17): `cmp38_eq32`, `or`, `csr.w`; base-zero `st.d` остаётся
  'assumed' (P4 не выполнялся) — `050` §3.

## 4. Dispatch-карта (вход команд FW, L4)

| элемент | dc / адрес | смысл |
|---|---|---|
| Дверь | fn 0xd4d58 | CR 0x23fc (bit0=valid, lo16=opcode); вход из ROM/iron — 0 ссылок в MAIN_CODE; live-жива (146 событий) |
| Whitelist | 0xd4714 | допустимые opcode (0x9001 разрешён); обёртки 0xd4864/0xd48e8 (гейты RAM w0x457 + CR 0x23f4) |
| Диспетчер таблиц | 0xd4a24 | jump-таблицы @0x3147c0 (0x8400-05) / @0x3147d8 (0x9001-06); rt-записи; `ret.r` no-link; 0x9001 → `call 0xd3804` @0xd4ac4 |
| Рег-доступ | 0xd3804 | hdr CR 0x2004; внутри — L3-хук 0xd3850; далее is_flash 0xd31b8 (таблица @0x314714) → 0xd3388/0xd3600 |
| Кадр команды | **CR-окно 0x2014..0x2310** | инлайн в CR, НЕ стек-копия — главная структурная дельта vs 4030 |
| extm-mailbox | 0xd4948 | пара CR 0x23e8/0x23ec → DMA 0x109f0 |
| cmdif_driver | 0x9464c..0x95400 | FSM миссий (S1/S2-аналог) |
| AN-FSM | 0x1bdfa0 | self-post 0x35 @0x1bd5a8; цикл ~0.4 с |

Хук-кандидаты: **H0 0xd3850** (live-доказан, эталон — `040`), **H2
0xd4df4** (call 0xd48e8; все разрешённые команды; r4=opcode, r5..r10 dead —
flow-скан перед реализацией), **H6 AN-FSM** (напр. 0x1b9da4; «вечный
читатель» ~0.4 с; условен — только при активном AN-loop).

## 5. Read-каналы (память FW → хост)

| канал | слов/итерацию | когда исполняется | статус |
|---|---|---|---|
| **emit7 (рекомендован)** | **7** | по H0/H2-триггеру (register-команда) — поздние runtime-значения по определению | live (семья emit доказана v3) |
| CR-слот | 1 (0x23f8) | runtime-хук (занят с boot'а: runtime-счётчик/маска — **эратата B2**, не переопределять) | live (0x23f0 занят маркером) |
| **CR-резерв 0x2314..0x23e4** | **до 53** (0x35 hex — эратата «35») | **boot-детур (ранние значения!)** или runtime-хук | **live-proven B2: boot-слова пишутся стабом C1 при буте, читаются VSEC в driverless-окне (полл #0 — первая хост-команда)**; негатив-контроль сток/v3 = 0 (селективность) |

Рецепт прикладного дампа (например, root-fix sfp28-ib-node: low-RAM bitset
от 0x0D600C (4 сл; точный список подтверждает потребитель), гейты
0xE2B4/0xD5DC, rec-поля — ~6 слов): H0-хук + ld.d (offset-batching) +
emit7 одним событием; при необходимости повторить с другими адресами
(boot-время значения могут быть нулями — читатель runtime). Полный
замкнутый dump-цикл (посев → хук → ответ, каналы C/B + негативный
exec-результат R-A4b) — `050-cx4lx-dump-cycle.md`.

## 6. Доказательная база

- Отчёты цикла: `docs/superpowers/reports/cx4lx-detour-l{0,1,2,3,4}.md`
  (+ журналы `docs/superpowers/journal/2026-10-11-cx4lx-detour-l*-task-01.md`,
  спека `docs/superpowers/specs/2026-10-11-cx4lx-detour-design.md`).
  Дальнейшие фазы: boot-окно/cable-path — `045`, dump-цикл — `050`.
- Хелперы: `scripts/probes/cx4lx-detour/` (l0_isa_audit, l1_geometry,
  l3_trace_recon, l4_dispatch_map, build_detour_v{1,2,3},
  build_cable_t2.py) + `scripts/probes/cx4lx-dumpcycle/`
  (build_dump_ra3.py — `050`).

## Постулаты / открытое

- **Вход cmdif_driver** (S1/S2-аналог в 14.32) — открытое.
- **Механизм S2-фризов CX-5 на Lx** — гипотеза-мера: «ноль доп-записей в
  пуш-кадр».
- **badc0ffe-читалка — не на хост-пути** `[факт, негатив]`:
  register-based flash access идёт мимо; 534K событий, 0 наших.
- **Exec-from-окна (0x2014..0x2310)** — закрыто негативом R-A4b:
  armed-триггер через хук с copy-loop стабом клинит CMDIF (wedge 4/4);
  безопасный путь «копия окно→кейв + исполнение из кейва» НЕ подтверждён —
  детали и эраты `050` §3. Голые armed-триггеры на copyloop-классе образов
  не пускать.
