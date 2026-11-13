# s1/ — пайплайн сборки S1-образов (on-demand iRISC, спека 2026-09-22)

Статус: **рабочие скрипты S1-сессии** (`ses_f3a2eefb…`), скопированы из
`/tmp/opencode/s1/` (2026-09-23) для сохранности; не продукт. Пути к образам
захардкожены (`/tmp/opencode/s1/*.bin`, md5-проверки в скриптах) — это
журнальные билдеры конкретных итераций. Общая схема пайплайна — PC4:
extract raw 0x03 → de-clcrc → патч → re-clcrc (per-line, seed 0x0000) →
section/entry CRC → `mlxfwutil.py verify --deep`.

## Скрипты

Проверенная цепочка (рабочий каталог) + RE-инструменты; superseded-итерации
— в `archive/` (git mv, доказательная база md5-цепочки ledger: root-cause
A/B v4c↔v4d воспроизводим только с архивным `build_s1_v4c.py`).
Мемо переноса: `docs/superpowers/memos/2026-09-24-s1-script-archive.md`.

| Скрипт | Назначение |
|---|---|
| `build_s1_redesign.py` | Redesign: ID-специфичные boot-safe стабы (capture только в ID2); v2-guided-база (бит-в-бит воспроизводим) |
| `build_s1_v4d.py` | v4d = v4c − ID2-хук: restore stock @0x0d3cf4 (3 слова) + FN_A-хук @0x18d964 + no-op detour-стаб @0x38d770 (теперь слот свободен от ID2-контекста). diff v4c→v4d = ровно 3 слова @0x0d3cf4. Образ md5 `c710012c…`; **BOOT OK** (root cause подтверждён A/B) |
| `build_s1_v4e.py` | v4e = v4d + capture в стаб @0x38d770: re-prologue + exfil (0x2380/84=ra, 0x2388=0x09320003, 0x238c=magic, 0x2390=flag; base r13) + jump-back → 0x18d970. **Без op-check** (op в FN_A-контексте статически неопределим; r6 — wild-load-риск) — селекция 0x0932 через quiescence + baseline/trigger + ra-4 = call 0x18d964. diff v4d→v4e = 13 слов @0x38d77c–0x38d7ac. md5 `662f593e…`; burned 2026-09-24 (recovery-путь docs/850-howto/100-cross-flash-ops §9), **BOOT OK**, G5: поток 0x0932 локализован (0x0e437c / fn 0x0e4250, BadParam-path); карта оставлена на v4e как база S2 |
| `scan_hooks.py` | Read-only: xref-скан jump/call → safe-zone стабы + декод v2 capture-стаба |
| `dec2.py` | Word-декодер (вариант с off14-форматированием; таргеты веток — старый баг). **Не двигать**: import-зависимость `build_s1_v4e.py` |
| `dump.py` | Дамп слов через `scripts/irisc/dis.py` |
| `analyze_r9_prolog.py` | RE: сохранение r9 в прологах хукнутых fn |
| `bounds.py` | Границы функций |
| `callsite_args.py` | Аргументы callsites |
| `xverify.py` | Кросс-верификация собранного образа (mlxfwutil verify) |

## archive/ (superseded, доказательная база)

| Скрипт | Назначение |
|---|---|
| `archive/build_s1.py` | S1 T3: S0-base + 3 хука + локатор 93 слова |
| `archive/build_s1_fixed.py` / `build_s1_fixed2.py` | Фиксы op-check офсета (+0x28 vs +0x70) |
| `archive/build_s1_bisect_nor14.py` / `build_s1_skipflag.py` | Диагностические bisect-образы |
| `archive/build_s1_noop_detour.py` | No-op detour (контроль детура) |
| `archive/build_s1_v3.py` | v3: guided + FN_A-хук @0x18d964 (FAIL: assert ext_synd 0x8494) |
| `archive/build_s1_v4.py` | v4: guided + FN_A-хук + cmp38/capture-стаб @0x38d770 (FAIL: ALLOC_UAR -110) |
| `archive/build_s1_v4b.py` | v4b: стаб = ret.d только (FAIL: то же -110). /tmp-копия была с битой строкой — репо-версия исправлена, rebuild byte-идентичен (md5 `7ace6354…`) |
| `archive/build_s1_v4c.py` | v4c: no-op detour-стаб (FAIL: -22, BOOT FAIL). Rebuild byte-идентичен (md5 `39cb367e…`). **Root cause**: слот 0x38d770 занимал задействованный v2 ID2-capture-стаб (хук @0x0d3cf4) — конфликт слота (журнал `2026-09-24-irisc-ondemand-s1-v4c-postboot.md`) |
| `archive/forensics_v4c.py` | Read-only: diff v2-guided vs v4c MAIN_CODE, дамп хуков/стабов (инструмент инцидента v4c) |
| `archive/dec_bisect.py` / `dec_noop.py` | Декод-верификация конкретных билдов |

Образы/выходы — в `/tmp/opencode/s1/` (в репо не кладутся).
