# 002. FW-гейт скорости IB: карта гейта (4030) и C12-аналог (CX-4 Lx 14.32)

> Источник: статическое RE MAIN_CODE 16.35.4030 (Ghidra + декодер iRISC
> `scripts/irisc/irisc_dis.py`) + live-доказательства iTrace (маска
> `0x4000C40 -l 0`) и CR-дампов — глава 3 арки «Трансиверы под IB»
> (спека `docs/superpowers/specs/2026-10-04-transceiver-ib-arc-design.md`),
> 2026-10-08..10; CX-4 Lx 14.32.1900 — арка cx4lx-sfp28-ib (2026-10-13/15).
> Журналы: `docs/superpowers/journal/2026-10-08-transceiver-ib-ch3-ghidra-gate-task-*.md`
> (01..12c12min, 12matrix, 12transition); финальные отчёты CX-4 Lx:
> `docs/superpowers/reports/cx4lx-sfp28-ib-node-v2.md` (§3–§5),
> `…-final.md` (сигнатура, iTrace-данные, 04t/04w), `…-04z-memo.md`,
> `…-variant-g.md`.

Связи: EEPROM-форматы и теорема SFP28 (другая половина дуги трансиверов,
включая перекодировку/QSA и образы c12min) —
`docs/250-re/100-formats/070-transceiver-eeprom.md`; iTrace-метод —
`…/065-fw-trace.md`; инъекции iRISC (доставка патчей) —
`docs/250-re/120-irisc/025-boot-injection.md`, trace-машина 14.32 —
`…/035-cx4lx-trace.md`; burn/FNP и лестницы отката —
`docs/850-howto/100-cross-flash-ops.md`; цепочка гейта end-to-end, стена,
итоги главы — `005-chain.md` / `010-wall.md` / `025-ch3-results.md`.

## 1. Цепочка (MAIN_CODE 16.35.4030)

```
классификация fn 0x28f880 → запись типа 0x940c+type·0x70 (терм IB = [+0x44]>>24)
  → set_pm_speed_and_width fn 0x25a5b0 → IB-ветка apply_stamping_ib fn 0x25a2f0:
      speed_enabled = requested & module_term(load dc 0x25a3e8-ec) & ~postfilter(0x25a560-7c)
  → 0: event 45 (6→0), serdes power-down, PLL close — порт Disable навсегда (Polling не наступает)
  → ≠0: open_pport fn 0x258ef0 (trace 0x259064): disable→polling → ib_speed_nego → Link_Up
```

## 2. Живые доказательства (iTrace, mask `0x4000C40 -l 0`)

| Шаг | D: сток QSFP AOC (живой) | A: SFP28 оптика (наш graft) | A после C12 |
|---|---|---|---|
| plug event 63 `ps=0x0→ns=0x6` | да | да, идентично | да |
| stamping до | `speed_enable=0x11f` | `0x10f` | `0x10f` |
| **stamping после** | `speed_enabled=0x1` | **`0x0`** | **`0xf`** |
| дальше | open_pport → nego → **4xSDR LinkUp за 4.4 с** | event 45, серды спят | **open_pport → Polling**, opcode 26→0 |

Переходная фаза снимается только re-plug-окном (админ-цикл PAOS на 4030
молча игнорируется; steady-state PM-тих даже на активных линках —
task-12matrix/12transition).

## 3. Патчи дуги (итог)

| Кандидат | Сайт | Вердикт |
|---|---|---|
| C4 | dc 0xa348 (геттер cap fn 0xa338) | опровергнут (return не у дел) |
| C6 | dc 0x254168/0x2541bc (SCS-фидеры) | **подтверждён — дисплей SCS** (0x0→0x1f на любом модуле) |
| C7 | fn 0x1eb7dc «зеркало B» (6 слов) | опровергнут (не тот потребитель) |
| C8 | dc 0x1edae4 (статус-слово sink) | опровергнут (sink не вызывается) |
| **C12** | **dc 0x25a3ec: `fcb1c083`→`0011001f`** (`addi r17,zero,0x1f`) | **ПОДТВЕРЖДЁН — гейт снят** (IB-путь only; port0-Eth/QSFP-логика не тронуты) |

## 4. Архитектурный вывод

Кремний/PM обеих карт умеет IB из коробки: cap-глобалы ПОЛНЫЕ даже на
SFP28-карте (`0x34cc=0x07270303`, `0x34ce=0x30c02055` — FDR10+FDR+EDR;
c9a2-дамп). «Отключение» IB — логическое, в одном месте штамповки
(2×2-матрица — §5: в steady-state мёртвый угол неотличим от рабочих).
C12 возвращает решение модулю-агностику.

## 5. 2×2-матрица легальных углов (steady-state; c11-matrix)

Четыре «легальных» угла (SFP28/QSFP × Eth/IB; все — билд 16.35.4030):
CR-дамп через VSEC + iTrace 110 с на угол. Источник (коммичен) — журнал
`2026-10-08-transceiver-ib-ch3-ghidra-gate-task-12matrix.md`; полная
таблица (все слова) — раздел «CR matrix» там же.

| Параметр | A: IB-SFP28 мёртвый (bazzite 03:00.1, graft+C6) | B: Eth-SFP28 живой (01:00.0, 25G) | C: Eth-QSFP живой (41:00.0, 100G) | D: IB-QSFP живой (41:00.1, 4xSDR) |
|---|---|---|---|---|
| Гейт-слово 0x3498 | 0x11 (b1=0, b2=0) | 0x11 (b1=0, b2=0) | 0x11 | 0x11 (via f1==f0) |
| Caps 0x34cc/0x34ce/0x34fb | 07270303/30c02055/00030101 | те же (A==B) | 07270303/**31c02055** (+b24)/00030101 | — (register file device-level) |
| Статус-слова S0/S1 (0x9e3c/0x9e48) | 0 / 0 | 0x2100 / 0 | 0x2100 / 0x800 | 0x2100 / 0x800 (via f1) |
| FSM модуля (iTrace) | 0→3→5→0 | 0→3→5→0, PM молчит | 0→3→5→0, PM молчит | 0→3→5→0, PM молчит |
| PHY_MANAGER / open_pport | 0 (event 45 в момент штамповки) | 0 при Active-линке | 0 при Active-линке | 0 при Active-линке |

**Выводы:** (1) `0x3498=0x11` на ВСЕХ углах, включая рабочий сток-IB —
b1/b2-гейт не дискриминирует; «спящая» цепочка — норма 4030. (2)
Статус-слова инертны (b0=0, b17-18=0) даже на Active-портах. (3) Дельта
caps C vs A/B — lineage (сток HPE vs наш graft), не dead-vs-working
(A==B побитово). (4) **Мёртвый угол A в steady-state неотличим от
рабочих** — расхождение существует только в момент штамповки (§2);
переходное окно = re-plug (PAOS-админ-цикл на 4030 молча игнорируется —
task-12transition). Наблюдатели гейта: iTrace-переход
(`065-fw-trace`) или CR-дамп инъекцией (c9a2, §4).

## 6. CX-4 Lx 14.32.1900 (FS3): C12-аналог и F1-таблица AN-sweep

На c1 (MCX4121A, 2×SFP28, FW 14.32.1900, FS3-образ) гейт IB — НЕ
штамповка §1, а две ступени: (1) порт молча gated (pm=0, «silent
no-link»); (2) после подъёма AN-пути — AN-sweep с F1-таблицей.

**C12-аналог (14.32/FS3/Lx) [F live]:** слово raw `0x37e0f0` (dc
`0x1f1f00`): сток `fcb1c083` → `0011001f` поднимает C12-гейт pm 0→2
(AN-путь активен; без пира — 0 событий, с пиром — AN-sweep). (На 4030
аналог — C12-штамповка, dc 0x25a3ec, §3.)

**F1-таблица-механизм (открытие цикла, T1a [V]):**
- F1 (fatal check) = lookup 7×3-бит в ОДНОМ RAM-слове `0x0D600C`
  (flag1; base 0x6b0060/mask 0xfffffffc), симметрично `0x0D6008`
  (flag0); **8 полей {0..7}**, ключ = индекс AN-sweep.
- Miss → ассерт `synd 0x1 / ext_synd 0x8bb4 / exit 0x0098c120
  (bank+0x800000) / callra 0x0098c0cc / vars (k,f)` — единственный
  сайт (литерал dc 0x18c128).
- c1 (SFP28): слово таблицы `0x5014` → miss **(6,1)** → ассерт на
  втыкании. 4030 (QSFP28, живой): **`0x46573201` — полная
  перестановка, покрывает все 8 ключей {0..7}** → F1-miss невозможен
  (pigeonhole). Проверенная живая дельта «4030 живой ↔ c1
  ассертящая» = ровно это слово; гейт 0xD5DC = 0 у обеих.
- **Доставка (урок 04w → F1-entry-hook):** boot-инжект (0x7ef0) не
  выживает (04t); cluster-entry 0x1ebe48 jump-трамплин (04w) —
  доставка провалилась (тот же (6,1) через 2.03 с). Рабочая точка —
  хук на ENTRY F1: `0x18c05c` → jump-трамплин в cave `0x31cba0`,
  стаб пишет `0x0D6008`/`0x0D600C` := `0x46573201` (04y, md5
  `4da96721…`). Верификация (T4b [V]): readback (iTrace emit7 var3) =
  0x46573201 на каждом F1-вызове; старый (6,1) не воспроизвёлся ни в
  одной топологии. Техника: entry-хук = jump (call затирает
  link-CSR 0xbc).
- Дальше по пути (после снятия F1-miss): unbounded AN-wait fn
  `0x243bec` (ветка arg1==1) на `csr0x1a4==2` — статус выставляет
  ЖЕЛЕЗО (писателя в FW нет ни в одном образе). SFP28-IB CX4-Lx
  handshake не завершает: вердикт **hardware** (T10, вариант «Г») —
  1-lane SFP28-PHY не выставляет csr0x1a4==2 для IB-AN (для EN —
  выставляет, 04y 3/3); 4-lane QSFP28-PHY — выставляет (QDR LinkUp,
  Phase VIII). MAIN_CODE SFP28/QSFP28-образов байт-в-байт идентичен,
  SFP/QSFP-ветки симметричны. bounded-wait-фикс 04z1 принят рабочим
  образом (boot-ассерт 0x857f — не-фатальный побочник, EN Active,
  AN graceful).
