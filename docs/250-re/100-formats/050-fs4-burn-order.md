# 050. FS4: инвариант burn-order (механика сектор-erase)

> Источник: спека `docs/superpowers/specs/2026-10-31-repack-burn-safety-design.md`
> (§1.1-1.2 механика/улики, §2.1-2.5 гейты/планировщик), разведка
> `docs/superpowers/journal/2026-10-31-repack-relocation-recon.md` §3
> (mstflint-механика + golden-числа v4), цикл repack-burn-safety
> (2026-10-31; live-валидация L2/L3 — журнал
> `2026-10-31-repack-burn-safety-task-06.md`). Реализация — mlxfwutil
> `burn_order_check`/`burn_damage_predict`/planner
> (tests/test_burn_order.py: TestBurnOrder, TestGates,
> TestRefsStocksCorpus, TestGoldenV4). CRC секций/записей — `025-crc.md`;
> укладка FS4 — `030-fs4.md`.

## 1. Механика (mstflint @1b8ac4b5)

`BurnFs4Image` пишет ITOC-секции **в порядке записей ITOC**, не по
адресам (`fs4_ops.cpp:2706-2724`), через `Flash::write` с
`readModifyWrite=false`: при входе в новый сектор — **erase всего
64KB-сектора без сохранения соседей** (`flint_io.cpp:742-752`, кэш
`_curr_sector`); DTOC-секции пишутся с RMW (соседи сохраняются) —
асимметрия. Read-back-verify (`mflash.c:416-448`) сверяет только текущий
чанк → повреждённые ранее-записанные диапазоны никто не перечитывает:
повреждение совместимо с «Burning OK» / `Restoring signature - OK`.
Гранулярность burn = **64K** (режим Fwm_64KB) независимо от hw-атрибута
SectorSize (live-полигон: `flint_oem hw query` дал SectorSize 0x1000, но
rb-readback совпал с 64K-моделью побайтово — task-06; параметр чекера
`--sector-size` для иных флешек).

## 2. Инвариант

Порядок ITOC-записей == **монотонный рост адресов** (контигуальный ран —
каждый 64K-сектор входит в write-поток ровно один раз). Нарушение =
«revisit»: erase уничтожает данные ранее писавшихся в сектор секций, не
переписываемых текущей записью. FS3 и FS4 — одна write-модель.
Вендорские стоки: **66/72** корпуса `refs/fw/**/fw-*.bin` (22 FS3 + 44
FS4) монотонны, нарушений 0.

- **Gap-fill релокация mid-list небезопасна при sector-revisit** — даже
  при 64K-выравнивании нового адреса: опасен повторный вход write-потока
  в уже посещённый сектор — последующие in-place записи ревизитят нижние
  сектора (v4: возвраты 0x32/0xeb; live-unsafe task-05: те же 0x32/0xeb
  на другой базе). Обратный переход в новый, ещё не писавшийся сектор
  чекером разрешён (tests/test_burn_order.py:135-137,
  test_jump_back_fresh_sector_ok).
- **Безопасные варианты:** рост секции внутри её 64K-сектора; полный
  монотонный reflow; перенос записи в конец ITOC + данные после max(end)
  по 64K-границе (планировщик mlxfwutil; live-доказано L3: флеш == образ
  побайтово, 0 урона, старое место 0xFF).

## 3. Гейты mlxfwutil (цикл repack-burn-safety)

- `verify` — burn-order-чек (нарушение → `RESULT: FAIL` rc 1);
- `inject`/`repack`/`resize` — предзаписной отказ rc 2 (`--unsafe-relocation`
  — обход legacy-аллокатором, research-путь с warning);
- любая релокация ⇒ автознак 0xA0 (`--no-autosign` — research).

FS3-leg (arc D task-5, 2026-11-12): те же гейты у `resize`
(repack_resize: shrink in-place / рост tail-placement) и FS3-веток
`repack`/`swap_repack` — дельта-анализ и решения в спека-аддендуме §9
`2026-10-31-repack-burn-safety-design.md`.

## 4. Live-доказанный эффект повреждения = soft-brick

Повреждённая карта ПОДНИМАЕТСЯ на FW из повреждённого банка: `dc` →
`Bad CRC` (INI стёрта), Rom Info в `q` утрачен (ROM_CODE-урон), link
ACTIVE, identity на месте (L2, task-06; restore обычным доступом).
«No-boot» на этом классе повреждений наблюдался исторически только на
S1/c178 (`docs/750-exp/100-dell-base-vpi-build.md` §3.1,
`docs/750-exp/110-dell-base-rework.md` §A/B.5); v4 — бут не проверялся
(карта в FNP, сразу перепрошита;
`docs/750-exp/175-irisc-injection-burns.md`, журнал
`2026-09-21-irisc-fnp-burn-verify.md` §15). Cold-POST/host-reboot
этим циклом не проверялись — no-boot на холодном старте остаётся
гипотезой.

## 5. Открытое: MCC-burn немонотонной укладки

Механика верифицирована на mstflint-путях записи (direct/legacy:
`--no_fw_ctrl`, `-apc`; L2/L3 — побайтовое совпадение predict vs flash);
plain-MCC restore known-good (монотонный образ) выполнялся — task-06,
«Restore после L2» (digest-гейт пройден). Не проверялось (вне скоупа
цикла, спека §4-конец) поведение MCC-burn на **немонотонной укладке**
(слот пишет running FW по MCC — исходников FW нет) — фиксировано как
открытый вопрос.

## 6. Скоуп-ограничение парсера

Signed-стоки без plaintext ITOC (CX-7 `fw-ConnectX7-*.signed.bin`:
ITOC-банк зашифрован, открыт только DTOC) mlxfwutil не парсятся —
корпус-тест допускает parse-отказ только с текстом `FS2 is not supported |
ITOC not found`; из 72 образов корпуса проверено 66, 6 outside-scope
(2 FS2 CX-3 + 4 CX-7 signed).
