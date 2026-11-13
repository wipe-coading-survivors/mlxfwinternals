# 045. CX-4 Lx: boot-окно/driverless-трейс + cable-path (Фазы VII–VIII)

> Источник: фаза VII (boot-окно) — отчёты
> `docs/superpowers/reports/cx4lx-detour-b{0,1,1b,2}.md`, спека
> `docs/superpowers/specs/2026-10-11-cx4lx-boottrace-design.md`, журналы
> `docs/superpowers/journal/2026-10-11-cx4lx-detour-b*-task-01.md`;
> фаза VIII (cable-path) — отчёты
> `docs/superpowers/reports/cx4lx-detour-t{0,1,2}.md`, спека
> `docs/superpowers/specs/2026-10-12-cx4lx-cablepath-design.md`, журналы
> `docs/superpowers/journal/2026-10-14-cx4lx-detour-t*-task-01.md`;
> тул — `crates/mlxscope` (`trace`: arm/drain/status; `dump`), билдер —
> `scripts/probes/cx4lx-detour/build_cable_t2.py`. Карта —
> `CARD_CX4LX_BCAT` (bazzite, 04:00.0).
> Связи: каркас/геометрия/CR-резерв → `030-cx4lx-detour.md`; trace-машина
> → `035-cx4lx-trace.md`; runtime-хук → `040-cx4lx-hook.md`; dump-цикл →
> `050-cx4lx-dump-cycle.md`; iTrace CX-5 →
> `docs/250-re/100-formats/065-fw-trace.md`; burn/банки/FNP →
> `docs/850-howto/100-cross-flash-ops.md`; железо Lx →
> `docs/750-exp/130-cx4lx-pcie-gen4.md`.

Дистиллированные итоги фаз VII (2026-10-11) и VIII (2026-10-14–15) как
факты; сырые детали — в отчётах/журналах выше.

## 1. Boot-окно и driverless-трейс (Фаза VII)

- **Сток-конвейер:** mstfwtrace ставит ТОЛЬКО маску — ICMD SET_ITRACE
  0xf003 {unit_mask u32, log_level u8, log_delay u16}; ринг — MTRC-регионы
  0x9040 CAP (ownership) / 0x9041 CONF (mode+log_size+trace_mkey) /
  0x9043 CTRL (arm), буфер через MTT-mkey. Ринг регистрирует mlx5
  (fw_tracer) при probe; **без драйвера mstfwtrace бесполезен** (live,
  B1). Маска живёт в FW-RAM (w2/w3 — `035`) и **слетает при любом
  FW-рестарте И при mlx5 unbind/rebind без рестарта** (live, B1).
- **Driverless-арм (V1-lite):** свой флоу без драйвера (порт mtrcdump
  синдиката): AllocPD → CreateMKey-MTT → CAP → CONF → CTRL → маска —
  `mlxscope trace arm`, **0.39–0.51 с** от доступности устройства
  (VFIO; IOMMU on на время). **Решение владельца 2026-10-14: IOMMU
  kargs на bazzite — ВКЛЮЧЕНЫ ПОСТОЯННО; revert kargs и ребут после
  задач НЕ делать** (достаточно rebind vfio↔mlx5). Окно наблюдения от
  FW t0: **~2.0 с** (vs 9–15 с с драйвером). Формат ринга (RE по живому
  дампову): записи 8B BE [hdr][data], типы 0xa2/0xa3 (string-слова,
  event_id) / 0xff (timestamp), tdsn/tmsn в hdr[15:0]; CORE-кадр
  (`035`) побит на записи.
- **Boot-окно (V2, C-B2 доказан):** boot-стаб на сайте C1 @dc 0x7ee4
  (boot-entry, live-proven ещё v1) пишет boot-слова в CR-резерв
  0x2314..0x23e4 (`030` §5); хост с mlx5-блэклистом читает их
  VSEC-поллом, **полл #0 = первая хост-команда FW** (mono ~20 с от
  power-on) — слова уже там, стабильны. Поймано: csr0x70@entry
  (0x00b1cba8, бит-в-бит 3 бута, на стоке 0), w0x2ef=0 (**развилка
  main-init = ветвь 0x7f94**), boot-ready магия, маркер B2.
  Негатив-контроль (v3 без reserve-писателя) — резерв 0: селективность.
- **Эраты B2:** C2 @0x8040 «безусловный хвост» НЕ исполняется —
  wait-loop 0x8024 паркует навсегда (7+ мин, 3 бута; эратата B0);
  0x23f8 занят runtime-счётчиком с бута; размер резерва — 0x35 hex
  = 53 слота (не «35»).
- **Восстановление при аресте бута:** авто-фолбэка на второй банк НЕТ
  (`docs/850-howto/100-cross-flash-ops.md` §7.1 — только
  burn-переключение); путь — ребут хоста + burn, далее FNP (там же §9).

## 2. Cable-path: ветвление QSFP↔SFP + QDR/FDR/Eth-дифф (Фаза VIII)

- **Ветвление типа — по identifier МОДУЛЯ, не плате** (T0): дескриптор
  RAM `0x942c+0x70·m`, word0 byte0 = SFF identifier (82 читателя);
  is_sfp fn **0x222670** — {0x03 (SFP/SFP+), 0x1B [H: SFP-DD]} +
  бит-тест порта @0x6776f+0x200·m; QSFP-сем. fn 0x222828 [0x0C..0x0E]
  + бит @0x4a17d+0x380·m; CMIS fn 0x2228a0 (==0x1E). **QSFP28 = 0x11 ∉
  SFP-множеству → SFP-ветка на QSFP-плате с QSFP-модулем не
  исполняется** (статика T0; live — SFP-паттернов нет ни в одном окне
  фазы, а единственное исполнение is_sfp-сайта — boot-init, T2d/T2c —
  дало verdict=0). Отдельного cage-гейта в детект-пути нет — бит-тесты
  per-port [H: capability/состояние].
- **MM SM: 21 состояние, state 8 = полный проход** (T2c): вход MM SM
  0x231910 читает state (5 бит, RAM 0x49e20+m·8) → непрямой jump через
  таблицу @dc **0x31930c** (состояния 0..20); state 8 = 0x231ebc
  MM_INIT_PLUGGED_IN — единственный с is_sfp-хвостом: CFG-выход на
  эпилог 0x233e94 только через хвост после call is_sfp **@0x233094**
  → сайт исполняется 1:1 с каждым исполнением state 8. Runtime
  hot-plug ходит **сокращёнными путями**: внешний писатель состояний
  между вызовами SM (асинхронные completions I2C/presence [H]) двигает
  состояние 1/2→19/13→20→5→8-rest мимо исполнения 8; полный проход
  (pages 0/255/3/240 + PARSE_PAGE ×6 + терминал 8→0 + H-DEC) — только
  на boot-init. **H-DEC = маркер полного MM-прохода** (за все прогоны
  1 исполнение — boot-init; hot-plug холодный/тёплый — 0; IB — 0).
- **Сток-подписи детекта различают модули БЕЗ хука** (T2d, холодные
  втыки Eth; тёплый путь = page-0-only + терминал 5 — ре-инициализация
  после port reset, не артефакт модуля):

  | ось | AOC QDR | FDR/56G DAC | 100G-оптика |
  |---|---|---|---|
  | page-чтения | 0/255/3 (без 240) | только 128 B (page не логируется) | 0/3/240 (без 255) |
  | PARSE_PAGE | ×6 | ×0 | ×3 |
  | init_sm терминал | 19→20→5→8 | 20→5→8 | 13×4→5→8 |
  | connector_type | 4 | 1 | 4 |
  | KR-лейны / вход | 0-3, ev62 (ps0→1) | 0-3, ev59 (ps1→3, walk до 6) | 0-1, ev62 + reversals |
  | speed_2_pll ETH | init 0xa001 → линк 0x8000 | init 0x1041 → линк 0x40 | init 0x6000a001; unplug 0x40000000 (=50G) |
  | Supported-словарь | 0xa000 (40G,10G) | — | 0x2024a101 (100G..1G) |
  | plug→init / init→UP | +1.5 с / +4.4 с | +1.0 с / +3.5 с | +1.2 с / +5.7 с |

  Точный GbE-декод битов 0x8000/0x1041/0x40 не верифицирован (PTYS в
  armed-окнах не запрашивались) `[постулат]`; якорь 0x40000000=50G
  (t2d3: PTYS oper + mstlink).
- **IB: QDR↔FDR** (T1 A/B/B3 + T2b): Enabled-маска модульно-зависима —
  AOC **0x07** без бита FDR10 (PDDR opcode 25) ↔ DAC **0x1f**
  (opcode 2); Supported 0x0f/0x1f; PTYS-admin 0x3f всегда → ограничение
  живёт в cable/PHY-пути детекта/AN, не в host-настраиваемом PTYS.
  **FDR-линкап не встаёт с двумя партнёрами** (CX-5 direct — B,
  InfiniScale-IV — B3): дискриминатор A vs B3 — свитч тот же, шнурок
  решает. Сигнатура зависания: вечный verifier-retry (input_event
  **0x3d**/ver 1 ≈ 90%: 89.7–93%), **cnf_test/agreed_ts3 недостижимы**,
  init-раунд 1469–1871 мс (QDR: 302–310 мс), скоростные слова 0xf
  (default_ts3/speed_enable). Успех QDR: agreed_ts3 **speed=0x7**,
  cnf_test ×91, **is_peer_legacy 0→1** (семантика [H] — исход дошедшей
  неготиации: peer-capability читается только после обмена; «легаси» =
  поколение/энкодинг пира). **chosen_mask=0x1 в обоих режимах — НЕ
  маркер отказа** (пересмотр T1-интерпретации, T2b-2). Ctx-слова H-AN
  (офсеты +0x58/+0x5c/+0x68/+0xa0/+0xa4): retry — константы бит-в-бит
  (cl 0x100, clp 0x430f, lane 0x10, type 0x1000010, index 0x01d80d41;
  детерминизм FW), успех — динамика (cl 0x100→**0x400**, clp бегущий
  +0x80000/раунд, type **0x1000034**, index 0x36ec4f41); чтение clp
  [H]: младший nibble ≈ speed_enable, биты 4-5 ≈ width_enable.
- **Eth vs IB** (T2d): Eth-AN-шторм **самоподдерживается без
  отвечающего партнёра** (~360 evt/s, петля AN 0x3→0x4→0x7,
  parallel_detect; дальний конец — IB-свитч); KR-startup-класс жив
  (входы ev59/ev62, walk по лейнам). init→линкап (помечены путь:
  тёплый = t2d3, холодный = t2d4): оптика **5.05 с тёплый / 5.7 с
  холодный**, AOC **17–33 с** (MM-done→UP 17.1 с / far-end→UP 32.6 с,
  тёплый; холодный init→UP 4.4 с), DAC **3.5 с холодный**;
  пост-линкап — полная тишина (IB: MM-crw 37/с + MAD + PTYS-hal).
  Линки: AOC 40G [presum], DAC 40G (бит 0x40 — следствие отсутствия
  56G-бита), оптика **50GbE Width 2x** (2×25G).
- **FDR10-on-IB — вне спецификации [H, владелец]**: согласуется с
  данными (AOC без FDR10-бита в Enabled; DAC биты 0xf, но
  chosen_mask→0x1 и вечный verifier-reject; LinkUp FDR не достигнут ни
  с одним партнёром). Eth-факультатив: **56G-бит найден** (T2c,
  директива владельца): FW_MAIN_CFG (ITOC **0x12**) @0x16000 size
  0xc00, lcl[0].eth_speeds_supported @abs **0x1630b: 0x3b→0x7b**
  (+bit6=56G; lcl[1] @0x16317=0x00 — не трогать) + пересчёт
  sec_crc/entry_crc (`docs/250-re/100-formats/025-crc.md`); runtime
  PTYS Enabled — производная (FW stamping: boot 0xf801f0d3→0x6000a001),
  отдельного PTYS-поля не нужно. Caveat
  `docs/750-exp/150-hw-verify-100g56g.md` §5: после 56G-патча на CX-4
  «родные медные кабели перестали признаваться» (A/B не
  верифицированы) — учитывать при 56G-тесте с DAC.
- **Инструментарий:** маски трейса — core 0x4404c60 (IB), расширенная
  **0x24404efc** для Eth (= core + eth_speed_nego 0x80 + kr_startup
  0x20000000 + SerDes 0x200 + 0x8/0x4; kr-класс обязателен — Eth-AN
  прогоняет KR-startup FSM); UTC-якоря `date -u` на арм/дрейн —
  привязка событий владельца к рингу (часы владельца ~2 с опережают
  хост); IOMMU-kargs постоянны, ребут между задачами не нужен (§1).
- **Образ `cx4lx-cable-t2-an5.bin`** (md5 `2e863105…`; сборка T2a,
  burn T2b-1 → банк A активен [на момент фазы; текущее состояние банков —
  `050` §3]): H-AN emit5 @0x1b9da4 (маркер 0x00ae58cd, 5 ctx-слов за
  событие) + H-DEC emit2 @0x233094 (маркер 0x00ad7547), кейв 23/24 сл;
  **линкапу не мешает** (QDR LinkUp — T2b-2, Eth 50G — T2d). Билдер
  `scripts/probes/cx4lx-detour/build_cable_t2.py` (прецедент-тест —
  `emit_stub("H-AN")`, скилл `irisc-asm`); откат — свежий ri
  (no-fw-backup). Per-plug маркер, если понадобится, — готовый кандидат
  C1 @0x231a64 (call 0x2347ec в state 1 — первый I2C-оп каждой
  последовательности детекта, все типы модулей; T2c §в): **re-hook
  H-DEC не нужен**.
