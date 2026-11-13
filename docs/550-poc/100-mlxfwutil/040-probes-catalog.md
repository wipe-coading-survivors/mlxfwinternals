# 040. Каталог пробников `scripts/probes/`

> Источник: перенос тулинг-разделов 90 §6 (`patch_56g.py`) и 95 §4
> (`irisc_addr_scan.py`; диспозиция спеки restructure §4.5 — merge обоих)
> со сверкой списков источников с фактическим `scripts/probes/` (30
> однофайловых пробников + 16 подкаталогов; первичные свидетельства —
> шапки скриптов, `scripts/probes/README.md`, `scripts/probes/JOURNAL.md`,
> git-даты добавления). Каталог — референс: один инструмент = одна строка;
> для каждого — что делает (вход → выход) и какой док/журнал им получен.
> Пробники — референс/архив фазы 1 (там же, README): оракул для
> `mlxfwutil.py`/Rust-тула, не продукт; без внешних зависимостей (Python 3).
>
> Связи: ini/0x30 — `010-ini-mapping.md`; патч-матрица CRC —
> `020-patch-matrix.md`; подпись — `030-signing-notes.md`; факты форматов —
> `docs/250-re/100-formats/`; iRISC-метод — `docs/250-re/120-irisc/`;
> cable-gate — `docs/250-re/130-cable-gate/`; burn-циклы инъекций —
> `docs/750-exp/175-irisc-injection-burns.md`.

## 1. Сверка источников с каталогом

| Инструмент/группа | 90 §6 | 95 §4 | На диске | Диспозиция |
|---|---|---|---|---|
| `patch_56g.py` | ✓ (тема §6) | — | ✓ | §4 |
| `toc_probe.py` | ✓ (верификация патча §6) | — | ✓ | §2 |
| `irisc_addr_scan.py` | — | ✓ (тема §4) | ✓ | §5 |
| Ghidra-скрипты (`scripts/ghidra/*.java`) | — | ✓ | ✗ (не в `probes/`) | §7 |
| live-тулинг хоста (mstreg/`mstflint q`/mstconfig/mstmread/mlx5cmd) | — | ✓ | ✗ (инструменты mstflint/MFT) | §7 |
| `tests/test_cable_gate.py` | — | ✓ | ✗ (тесты репо) | §7 |
| Остальные 27 `.py` + `gate-specs/` (рождены позже источников) | — | — | ✓ | §2–§6 (все тривиально описуемы по шапкам) |
| 15 подкаталогов-кампаний (cx5-*, cx4lx-*, c1-dualib) | — | — | ✓ | §7 |

Дедуп источников: множества инструментов 90 §6 и 95 §4 не пересекаются —
каждый инструмент входит в каталог один раз; связки «инструмент 90 §6 /
95 §4» отмечены метками «из 90 §6» / «из 95 §4» в строке.

## 2. Парсеры форматов (семейство `toc_probe`)

Вход всех — образ `.bin` (или пара), выход — текстовый дамп/таблица.

| Инструмент | Вход → выход | Происхождение (что им получено) |
|---|---|---|
| `toc_probe.py` | маги FS2/3/4/5, поиск ITOC/DTOC, парсинг записей, сверка header/entry/section CRC (`crc16_mlx`); базовый модуль остальных пробников | фаза-1 верификация (README probes, 2026-09-06) → `docs/250-re/100-formats/` (`…/005-detect.md`, `…/015-fs3.md`, `…/020-fs3-sections.md`, `…/025-crc.md`, `…/030-fs4.md`, `…/060-chip-map.md`); эмпирика DTOC по чипам — 90 §5.1; CRC-модель — `docs/250-re/100-formats/025-crc.md` |
| `fs2_gph_probe.py` | минимальный FS2-парсер: цепочка GPH-секций — list / extract (по типу/индексу) / dump-all | журнал `docs/superpowers/journal/2026-10-24-cx3-pcie-lineage-re.md`; формат GPH — `docs/250-re/100-formats/010-fs2.md` |
| `section_meta_probe.py` | по каждой секции ITOC/DTOC: размер, head-гекс, авто-классификация (iRISC-код / данные / zlib / option ROM / crypto / erased / zero / empty) + мета известных секций (PSID, keypair_uuid, ROM vendor:device); FS3+FS4 | сигнатуры/домены исполнения — `docs/250-re/100-formats/040-fs4-domains.md` (2026-09-20); zlib-классификатор 0x30 — `020-patch-matrix.md` §3 |
| `iron_boot_probe.py` | «IRON»-часть бут-цепочки: таблица boot-секций ITOC (type/flash-size/load/entry/presence) + байт-поиск SHA-256/512 K-констант и H0-хешей в кодовых секциях, RESET_INFO (0x20) и boot-регионе | `docs/250-re/100-formats/040-fs4-domains.md` (2026-09-20, 9 образов) |
| `dtoc_diff.py` | диф DTOC-секций (device data) пары FS4-образов, `--hex` по имени секции | цикл доп. исследований 90–94 (git 2026-09-07); внешних ссылок в доках нет — референс |

## 3. Подпись/идентичность

| Инструмент | Вход → выход | Происхождение (что им получено) |
|---|---|---|
| `sig_probe.py` | секции подписи 0xA0–0xA7 (заполненность/размеры) + флаги IMAGE_INFO (mcc/signed/secure), PSID/name/desc по набору образов | README probes (2026-09-06) → `docs/250-re/110-signing/005-mechanism.md` |
| `fb_probe.py` | ITOC через HwPointers (fallback — поиск заголовка) + секции подписи по layout (keypair_uuid), IMAGE_INFO, FW_BOOT_CFG (device_id/subsystem) — вендорские образы Dell/HP/Facebook | README probes (2026-09-06) → `docs/250-re/110-signing/005-mechanism.md`, `…/025-secure-boot.md` |
| `parse_imageinfo.py` | дамп IMAGE_INFO + диф FW_BOOT_CFG и секций подписи пары образов (офсеты захардкожены под пару CX-6Dx AE/AC) | README probes (2026-09-06) → `docs/250-re/110-signing/025-secure-boot.md` |
| `sign_diff.py` | байтовые диф-диапазоны пары образов | README probes (2026-09-06) → `docs/250-re/110-signing/025-secure-boot.md` |
| `verify_sha.py` | пересчёт SHA-256 секции 0xA0 по образу с маскировкой magic/устройства/0xA0; бит-в-бит расчёт не свёрстан (маски/size) | README probes (2026-09-06) → `docs/250-re/110-signing/010-payload.md`; реаттрибуция нюанса (дест @+0x20) — цикл burn-digest, `020-patch-matrix.md` §4 |
| `inject_guids.py` | GUID/MAC → mDevInfo (0xE1) + копия в 0xE0 + пересчёт CRC; обёртка над `mlxfwutil.py guides`; только offline (burn блокирует hashes table CRC) | `docs/750-exp/140-post-fnp-guid-desync.md` §8/§8.7 |

## 4. Патч-билдеры (образ → модифицированный образ / спека)

| Инструмент | Вход → выход | Происхождение (что им получено) |
|---|---|---|
| `patch_56g.py` | **из 90 §6**: ITOC → секция 0x12 → ожидаемый `lcl`-байт по PRS (пара со стридом 0xC) → патч `| 0x40` (бит 56G) → пересчёт sec_crc/entry_crc → образ; `--analyze/--dry-run/--port`; PRS-текст и подпись намеренно не трогает | 90 §6 (перенос: `docs/250-re/130-cable-gate/015-speed-bits.md` §3, `docs/250-re/100-formats/067-prs-zlib.md` §3); проверка на железе — `docs/750-exp/150-hw-verify-100g56g.md` |
| `graft_4706.py` | CX-4 «код C (4706) + конфиг A (2302)»: v2 — копирование ВСЕХ config-секций A (0x08/0x09/0x11/0x12) + lcl[0]=0xfb + 0x10 sub/PSID | `scripts/probes/JOURNAL.md` (апгрейд CX-4 4706, 2026-09); итог — `docs/850-howto/140-fw-upgrade.md` |
| `upgrade_base.py` | CX-4Lx-гибрид: база 14.32.1912 + идентичность/скорости/PCIe карты 0x1013 (консервативно — только проверенно-стабильные одиночные поля) | цикл 90–94 (git 2026-09-07); 14.32 отложен — `docs/850-howto/140-fw-upgrade.md` |
| `graft_4030_aca.py` | «synthetic 4030-ACA»: 4030-CDA base + ACA-бордпрофиль из as-found ri (фикс no-boot) | журнал `docs/superpowers/journal/2026-10-08-transceiver-ib-ch3-ghidra-gate-task-03b.md`; итог — `docs/250-re/130-cable-gate/025-ch3-results.md` |
| `cable_gate_patch.py` | применение patch-spec JSON к MAIN_CODE (dc-офсеты, de-framed view): decrc → check/patch → re-clcrc-фрейминг (64+2+2) → ITOC entry CRC → verify | глава 3: `docs/250-re/130-cable-gate/025-ch3-results.md`; журналы `docs/superpowers/journal/2026-10-08-transceiver-ib-ch3-ghidra-gate-task-06.md` и далее (task-09/12*) |
| `gate-specs/` | JSON-спеки патчей MAIN_CODE (dc-офсеты; `expected_before` самопроверяется `cable_gate_patch.py --check`) | глава 3 — `docs/250-re/130-cable-gate/025-ch3-results.md` |
| `c9_injection_build.py` | сборка спеки C9a runtime-инъекции: boot-detour + 2 scheduler-хука + 39-word dump-routines, протокол host-CR 0x23f0, guard 0xbadc0ffe | `docs/250-re/120-irisc/025-boot-injection.md`; журнал `docs/superpowers/journal/2026-10-08-transceiver-ib-ch3-ghidra-gate-task-12c9.md` |
| `c9a2_injection_build.py` | C9a-v2: тот же шеллкод на текущей bazzite-линейке (base 4030graft…), дельта — dump-таблица (слоты 26–31) | там же (`025-boot-injection.md`, журнал task-12c9) |

## 5. iRISC-RE-сканы (код-секции, offline)

| Инструмент | Вход → выход | Происхождение (что им получено) |
|---|---|---|
| `irisc_addr_scan.py` | **из 95 §4**: локатор ссылок на адрес/строку в iRISC-коде; режимы `words16` (lo16/hi16-скан; over-matches — call/addi), `words32rel`/`words32abs`, `ldb`, `set3`/`set2` (set-пары), `build` (whole-image build-скан по всем ITOC-секциям) + pair-детектор | фаза A 95 (журналы `docs/superpowers/journal/2026-09-16-ib-cable-gate-re3.md`, `…/2026-09-16-ib-cable-gate-re4.md`); перенос — `docs/250-re/130-cable-gate/005-chain.md` §1, `010-wall.md` §2 |
| `irisc_opcode_scan.py` | сайты iRISC-инструкций с 16-бит immediate из заданного набора (op-спектр iRISC.slaspec; вход — de-clcrc бинарник) | журнал `docs/superpowers/journal/2026-09-20-irisc-4030-qft-handler-re.md` (диспетчер PCIe-команд) |
| `irisc_loadgrid.py` | перечисление data-load'ов (ld.d/ld.b/lw.r) в MAIN_CODE + эффективные адреса для кандидатной data-base (вход — dc-вид) | глава 3 task-05: журнал `docs/superpowers/journal/2026-10-08-transceiver-ib-ch3-ghidra-gate-task-05.md`; op-семантика — `docs/250-re/120-irisc/010-isa.md` |
| `sha_anchor_scan.py` | серии ≥4 подряд констант SHA-256/SHA-1/SHA-512 (BE/LE) в кодовых секциях — якоря hash/digest-кода; dc-пространство для clcrc=1 (0x03) | burn-digest task-03: журнал `docs/superpowers/journal/2026-10-28-burn-digest-gate-task-03.md`; отчёт `docs/superpowers/reports/2026-10-28-burn-digest-upgrade-code-pseudo.md` |
| `wall8k_scan.py` | retest 8008-стены: clcrc-deframe MAIN_CODE + скан пар addi+addi.hi + карта сайтов (`8008_site_map.json`) | журнал `docs/superpowers/journal/2026-10-15-8008-wall-retest.md` (стена снята — артефакт метода); итог — `docs/250-re/130-cable-gate/010-wall.md` |

## 6. Свипы/дифы по наборам образов

| Инструмент | Вход → выход | Происхождение (что им получено) |
|---|---|---|
| `cable_gate_diff.py` | chunk-диф MAIN_CODE (0x03) 8008↔1012 (гейт есть/нет, одна плата MCX512A-ACA); офсеты секц.-относительные | фаза A 95: журнал `docs/superpowers/journal/2026-09-16-ib-cable-gate-patch-task-01.md`; перенос — `docs/250-re/130-cable-gate/010-wall.md` §1 |
| `sweep_speed_fields.py` | кросс-образный свип PRS-полей management speed (link_speed_ena/ext_ena/ext_sup/supported; CX-4/CX-4Lx) | cx4lx-56-100g task-1: журнал `docs/superpowers/journal/2026-10-07-cx4lx-56-100g-task-01.md`; отчёт `docs/superpowers/reports/cx4lx-56-100g.md` |
| `sweep_ib_mask.py` | кросс-образный свип байта IB-enabled маски (биты SDR..EDR; цели 0x1f/0x3f) | task-2: журнал `docs/superpowers/journal/2026-10-07-cx4lx-56-100g-task-02.md`; отчёт там же |
| `diff_1900_1912.py` | диф 1900↔1912 (FS3) + IB-mask sweep: config-байт vs MAIN_CODE (16-MiB flash-dump слот A) | task-4.6: журнал `docs/superpowers/journal/2026-10-07-cx4lx-56-100g-task-04b.md`; отчёт там же |
| `cx4lx_gen4_window.py` | классификация слов CR-window дампов CX-4/Lx Gen4 (unmapped/пуст/…) + 6-бит speed-поля + предикат stop-таблицы | `docs/750-exp/130-cx4lx-pcie-gen4.md` (спека 2026-10-24-cx4lx-gen4-window, task 3) |
| `rate_param_trace.py` | парный диф Gen3↔Gen4 SKU-секций (классификация по карте полей; неклассифицированное — кандидаты speed-data) + rate-scan (GT/s, MHz; BE/LE 16/32) | rate-knob task-3: журнал `docs/superpowers/journal/2026-10-24-pcie-phy-rate-knob-task-03.md`; `docs/750-exp/130-cx4lx-pcie-gen4.md` §3 |
| `scan_0c.py` | сканер 16B-слотов PCIE_PHY_UC_CODE-сигнатур (op-семьи 0x50–0x7f) по raw-образам — включая образы вне ITOC-тулинга | rate-knob task-4: журнал `docs/superpowers/journal/2026-10-24-pcie-phy-rate-knob-task-04.md`; формат — журнал `docs/superpowers/journal/2026-10-24-pcie-phy-uc-format-re.md` |

## 7. Не в каталоге

- **Ghidra-скрипты** `scripts/ghidra/*.java` (**из 95 §4**): DumpRange,
  CheckSites, DumpFuncs, TopFuncs, FanIn, CollectRefs, DumpConstRefs,
  Callers, PreFunc, Disasm — RE-конвейер в другом каталоге (не probes);
  конвейер — `docs/250-re/120-irisc/020-ghidra-pipeline.md`.
- **Live-тулинг хоста** (**из 95 §4**): `mstreg -a <adb>`, `mstflint q`,
  `mstconfig` (read-only), `mstmread`, mlx5cmd/VFIO — инструменты
  mstflint/MFT на хосте, не пробники репозитория.
- **`tests/test_cable_gate.py`** (**из 95 §4**): тесты репозитория (pytest),
  не пробники.
- **15 подкаталогов-кампаний**: `c1-dualib`, `cx4lx-an`, `cx4lx-detour`,
  `cx4lx-dual-vpi`, `cx4lx-dumpcycle`, `cx4lx-sfp28-ib-node`, `cx5-clever`,
  `cx5-cond-stub`, `cx5-door-detour`, `cx5-fuzz4`, `cx5-fuzz5`,
  `cx5-icmd-door`, `cx5-isa-max`, `cx5-isa-max-b`, `cx5-successpath` —
  многофайловые тулкиты кампаний iRISC-инъекций/ISA-цензуса (builder +
  recon + векторы + манифесты); канон методов —
  `docs/250-re/120-irisc/` (`025-boot-injection.md`, `030-cx4lx-detour.md`,
  `050-cx4lx-dump-cycle.md` и др.) и
  `docs/750-exp/175-irisc-injection-burns.md`; одно-двухстрочным каталогом
  не покрываются, вне scope полки mlxfwutil.
- `README.md`, `JOURNAL.md`, `__pycache__/` — не инструменты: README/
  JOURNAL — первичные свидетельства этого каталога.
