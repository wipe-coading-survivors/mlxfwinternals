# 000. Pinned revisions: сводная всех `refs/src/*`

> Источник: git-проверка каждого чекаута `refs/src/*` (rev-parse / tag /
> log / status, 2026-11-07; журнал
> `docs/superpowers/journal/2026-11-07-restructure-external-task-01.md`);
> перенос таблицы 30 §9 (исходная проверка 2026-09-06). Назначение —
> единая точка «какой rev фактически лежит в `refs/src`»; разборы самих
> репо — в кластерах ниже.
>
> Связи: карта исходников mstflint — `100-mstflint/010-walkthrough.md`,
> OSS vs MFT — `…/020-oss-vs-mft.md`; syndicate-репо —
> `120-syndicate/010-mlx5fw-mlx5cmd.md`; cx5-тул и
> BeTeP-скрипты — `110-misc-tools/010-cx5-gen4-tool.md`,
> `…/020-betep-scripts.md`.

## Таблица ревизий

| Репо (`refs/src/…`) | Origin | HEAD | Дата HEAD | Лицензия | Прим. |
|---|---|---|---|---|---|
| `mstflint` | github.com/Mellanox/mstflint | `a2b9858b` (lightweight-тег `v4.37.0-1`) | 2026-08-31 | dual GPL-2 / BSD (`LICENSE`, `COPYING`, `license_map.yaml`) | дерево чистое; вендор-сборка — из потомка `1b8ac4b5`, см. ниже |
| `irisc-research-syndicate_mlx5fw` | github.com/irisc-research-syndicate/mlx5fw | `05378b4` | 2024-11-09 | файла лицензии нет | |
| `irisc-research-syndicate_mlx5cmd` | github.com/irisc-research-syndicate/mlx5cmd | `f0f095b` | 2026-09-20 | файла лицензии нет | исторический разбор (вендор удалён 2026-11): ветка `wip-mlxini-mtrc-tools`: 1 локальный коммит поверх upstream `67617d1` (WIP mtrcdump/regdump) + незакоммиченные правки (`src/commands.rs`, untracked `src/bin/query-flow-table/`) |
| `Mellanox-ConnectX-5-PCIe-Gen-4-Enablement` | github.com/Bulls729/Mellanox-ConnectX-5-PCIe-Gen-4-Enablement | `ca701eb` | 2026-07-09 | MIT (`LICENSE`) | |
| `BeTeP-STH_mft-scripts` | github.com/BeTeP-STH/mft-scripts | `4d88ae2` | 2020-06-07 | файла лицензии нет | |
| `iproute2` | github.com/iproute2/iproute2 | `d1341d07` | 2026-10-26 | GPL-2 (`COPYING`) | нет в 30 §9 — добавлено по факу |
| `TransceiverTool` | github.com/robinchrist/TransceiverTool | `811da32` | 2026-09-25 | MPL-2.0 (`LICENSE`) | нет в 30 §9 — добавлено по факту |
| `linux` (контейнер) | — | `linux/linux`: `d135ab453a74` | 2026-10-26 | GPL-2 (`COPYING`) | контейнер из трёх деревьев: `linux/` — полный git-чекаут `github.com/torvalds/linux` (describe `v7.3-16755-gd135ab453a74`); `linux-6.18/`, `linux-7.2/` — частичные снапшоты (`drivers/` + `include/`, там mlx4/mlx5/mlxfw/mlxsw) без `.git` |

## Расхождения с 30 §9 (разрешены по фактическому HEAD)

- **mstflint**: 30 §9 → `1b8ac4b5` (тег `v4.37.0-1.3`); фактический HEAD
  чекаута → `a2b9858b` (тег `v4.37.0-1`). Оба коммита в репо: `1b8ac4b5` —
  upstream-потомок HEAD (merge relicense-dual2-master), несёт локальные теги
  `v4.37.0-1.{1,2,3}`; именно на нём пинирована вендор-сборка (ниже).
- **mlx5cmd**: 30 §1/§9 → `67617d1` (upstream master); фактический HEAD →
  `f0f095b` — локальная ветка `wip-mlxini-mtrc-tools` поверх `67617d1`.

## Вендор-патчи mstflint (provenance сборки)

Сборка — сиблинг `mstflint-container`: Makefile пинирует
`MSTFLINT_TAG ?= v4.37.0-1.3`, SHA `1b8ac4b520390563ff0822d472a54895d033d143`
(merge relicense-dual2 — первый полностью dual-licensed коммит). Патчи —
`patches/` сиблинга; артефакты: образ `mstflint:4.37.0-1.3`, AppImage
`mstflint-4.37.0-1.3-x86_64.AppImage`.

- `patches/mstflint-4.37.0-1.1-data-path-env.patch` — путь к data-файлам
  (DB/CSV/ADB/efuse) из env `MSTFLINT_DATA_PATH`; ib*-обёртки
  infiniband-diags через env `IBPATH` (самодостаточный AppImage). Журнал:
  `docs/superpowers/journal/2026-10-04-mstflint-ibnodes-ibpath.md`.
- `patches/mstflint-4.37.0-1.2-secure-read.patch` — dc/ri на secure-fw-карте
  через MCC-путь без ключа. **Суперседирован патчем -1.3** (в build-контекст
  не копируется; файл сохранён для истории).
- `patches/mstflint-4.37.0-1.3-secure-read-flag.patch` — REPLACES -1.2: та же
  MCC-механика dc/ri, но за явным ключом `--mcc_read`; default = сток.

Механика MCC-read, семантика ri, live-тайминги и Containerfile-гейты — не
здесь: `docs/850-howto/180-securefw-recipes.md`,
`docs/750-exp/170-securefw-live-gates.md`; журналы циклов securefw-read
(2026-10-29) и cx6dx-introspection (2026-10-30) — `docs/superpowers/journal/`.
