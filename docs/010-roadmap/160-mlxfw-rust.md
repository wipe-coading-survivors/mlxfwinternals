# 160-mlxfw-rust

**Статус:** seed
**Цель:** финальный инструмент `mlxfwutil` на Rust — перенос семантики
Python-PoC: байтовые обёртки без внешних Mellanox-зависимостей, тот же
round-trip-набор как тесты (cargo test), CLI `extract`/`inject`/`psid`/
`info` + `--analyze`, документация; поведение идентично PoC на тех же
образах.
**Критерии закрытия:** cargo test зелёный; поведение идентично PoC на тех
же образах.
**Фазы/задачи:**
- [ ] перенос семантики PoC на Rust; байтовые обёртки без внешних
      Mellanox-зависимостей (mstflint — эталон, не FFI; FFI-вариант
      `libmlxfwops` — допустим, если фаза 2 покажет, что проще)
- [ ] тот же round-trip-набор как тесты (cargo test) + тест на CX-6Dx PLDM,
      если формат окажется PLDM-обёрткой над FS4
- [ ] CLI: `extract`, `inject`, `psid`, `info` (ITOC-дамп), `--analyze`
- [ ] документация: `mlxini/README.md` (или `docs/750-exp/100-dell-base-vpi-build-mlxini.md`)
**Семёна:** ROADMAP-фаза 3 «`mlxini` Rust (финальный инструмент)» —
единственная незакрытая фаза исходного ROADMAP; предшественник —
Фаза 2 Python-PoC (закрыта 2026-09-15; `mlxfwutil.py` остаётся в репо как
референс-реализация).
**Связи:** `mlxfwutil.py` (PoC-референс), `crates/`, `docs/150-external/120-syndicate/010-mlx5fw-mlx5cmd.md` (irisc mlx5fw
Rust/deku — основа Rust-тула), `docs/750-exp/100-dell-base-vpi-build`; naming (roadmap-restructure.md
§4): зафиксировано `mlxfwutil.py` (мемо 2026-11-09; кол `mlxfwlib.py`
отвергнут), `mlx-fw-tui` — гипотетический
Rust TUI по образцу uefi-tui (github.com/wipe-coading-survivors/UEFIPatcher,
`crates/uefi-tui`); предпосылки для Rust-версии тают, но TUI-роль
(настройка прошивок) их повышает.

