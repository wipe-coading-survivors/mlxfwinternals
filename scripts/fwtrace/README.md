# fwtrace/ — live-скрипты iTrace (mstfwtrace) + 0x0932-проба под VFIO-окном

Статус: **рабочие скрипты live-сессий** (task-03 mstfwtrace-followup,
2026-10-08; эксперимент FLR/маска, 2026-10-09), перенесены из
`/tmp/opencode/` для сохранности; не продукт. **Live-HW — только через
субагента** (AGENTS.md `live-hw-subagent`, `docs/850-howto/100-cross-flash-ops.md`).

Канонические факты — `docs/250-re/100-formats/065-fw-trace.md`
(механизм, классы, level-семантика, v5r-vs-v5q, ограничения);
рецепт — `docs/850-howto/150-fw-trace.md`.

Карта (захардкожено в скриптах, под другую карту править):
- `DEV0=0000:81:00.0` — пробная функция (VFIO-окно, mlxscope, маркеры mstreg)
- `DEV1=0000:81:00.1` — **owner-функция, мstfwtrace всегда на DEV1**
- `IFACE=enp129s0f0np0`, `PROBE=/tmp/mlxscope/mlxscope`
  (md5 `298e841c7b8be4626fee3c5b509b2f04`, `crates/mlxscope`)
- `HEX` — кадр пробы B_F40 (0x0932, mode B)

## Скрипты

| Скрипт | Назначение |
|---|---|
| `stage-b-control.sh` | Контрольная трасса БЕЗ окна (v5r): ftrace on → `mstfwtrace -m ICMD -l 1` → маркеры mstreg MTRC_CAP ×5 → restore + carrier-проверка (рецепт mask-0) |
| `fwtrace-0932-window.sh` | Одно VFIO-окно + проба 0x0932 под трассой, маркеры ДО/ПОСЛЕ (task-03) |
| `stage-c-window.sh` | То же, run на v5q (task-03 §C): + liveness-gate до окна |
| `h1-stage2.sh` | Окно **без** re-apply маски (репродукция «тишины после FLR»; H1-эксперимент) |
| `h1-stage3-sanity.sh` | Sanity: трасса + маркеры ×3 **без** окна (ре-apply маски) |
| `h1-stage3-window2.sh` | Основной дискриминатор: окно + re-apply маски ПОСЛЕ FLR + маркеры |
| `h1-stage4.sh` | Окно + re-apply маски ВНУТРИ (in-flight, ~1 c после старта пробы) — опциональный |
| `h1-stage5.sh` | Финальный restore: mask 0, ftrace off, буфер чист + carrier-проверка + DO-state |

## Инварианты (нарушение = потеря данных / авария)

- mstfwtrace — только на owner-функции (`DEV1`); трасса читает ftrace-хвост
  ядренного драйвера (user-space ring-reader в mstflint нет).
- **Liveness-gate ДО открытия окна**: `mstfwtrace` обязан писать
  «Read new events» за ~5 c, иначе abort до окна (скрипты это проверяют).
- **Маркер-верификация ДО окна** (mstreg GET → 1 icmd-событие в логе):
  защита от setItrace-startup race (маска не применилась до первого события
  → run L0/L1-тихий; FLR маску НЕ сбрасывает — эксперимент 2026-10-09).
- VFIO-окно: `trap`-protected rebind (скрипты: `close_window` по EXIT);
  `new_id 15b3 1019` → unbind mlx5_core → bind vfio-pci → … → обратно +
  `remove_id`.
- Запрещено: all-classes `-m 0xffffffff` (флуд 152K+ — ринг залипает);
  `-l 2`+ (обходит class-маску, но гонит L0/L1, включая command-path).
- Restore после каждого run: `mstfwtrace -m 0 -l 0` (rc 124 = timeout,
  норма) → ftrace off → carrier-проверка (2× mstreg + 15 c → 0 mlx5_fw) →
  буфер чист (рецепт — `docs/850-howto/150-fw-trace.md`).
- БЕЗ burn/flash/mstconfig — скрипты не делают ничего, кроме ITACE-маски,
  ftrace, VFIO-бинда и пробы.

## Журналы (источники)

- `docs/superpowers/journal/2026-10-08-mstfwtrace-followup-task-03.md`
  (A/B/C: v5r→бёрн v5q→проба)
- `docs/superpowers/journal/2026-10-09-itrace-flr-mask-experiment.md`
  (H1-опровержение; ts-update = site 0x0001ce14, CMD_IF, L3)
