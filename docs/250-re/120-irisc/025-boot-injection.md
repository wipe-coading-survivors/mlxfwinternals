# 025. Boot-инъекция iRISC: детур MAIN_CODE + host-CR канал (CX-5)

> Источник: журналы
> `docs/superpowers/journal/2026-09-20-irisc-4030-qft-handler-re.md`
> (§21 маппинг, §25 register-write, §27 boot-точка/dead-code, §28 сборка v3),
> `docs/superpowers/journal/2026-09-21-irisc-fnp-burn-verify.md`
> (§5 гейты чтения, §7–§12 burn/marker, §13–§16 v4/v5); карта —
> `docs/050-hardware/100-inventory.md` (`CARD_CX5_EDR100`, BDF 81:00.0).
> Связи: адресные конвенции (BE, dc↔rt, CR↔RAM↔regspace, clcrc-фрейминг) →
> `005-endian-addressing.md`; ISA-семантики → `010-isa.md`; декодеры →
> `015-decoders.md`; Ghidra-верификация → `020-ghidra-pipeline.md`;
> burn-итоги v1–v5 → `docs/750-exp/175-irisc-injection-burns.md`; рецепт
> сборка+burn → `docs/850-howto/190-irisc-build-burn.md`; burn-order
> инвариант → `docs/250-re/100-formats/050-fs4-burn-order.md`.

Установленный результат (PoC УСПЕХ, 2026-09-21, `CARD_CX5_EDR100` /
81:00.0, MT28800 / ConnectX-5 Ex, non-secure): **произвольное исполнение
кода на iRISC CX-5 + host-видимый канал результата** — впрыскнутый
boot-time шеллкод отработал на firmware-boot и записал маркер `0xbadc0001`
в host-CR `0x23f0`; хост прочитал его через VSEC («МАРКЕР НА МЕСТЕ»,
«CODE EXECUTION CONFIRMED» — журнал 2026-09-21 §12). Метод iRISC Research
Syndicate (Bornhack 2024), воспроизведён (журнал 2026-09-20 §0/§9).

Сжато:

1. **Точка инъекции (§2):** MAIN_CODE 0x03, **dc 0x1d594** — `call 0x1e10c`
   (main-init), прямая цепочка после SP-init, исполняется на каждом boot.
   dc 0x1d598 (сразу после non-returning `call`) — **dead code** (self-jump
   `0x95000000`) — туда НЕ инжектить.
2. **Патч — 7 слов (§3):** dc 0x1d594 `0x940002de` → `0x940dc067`
   (call 0x38d730) + шеллкод 6 слов @ dc 0x38d730: `st.d` маркера в
   CR 0x23f0 + `jump 0x1e10c` (резюмирует main-init).
3. **Канал результата (§4):** host читает CR 0x23f0 через VSEC
   (space = CR 0x2). CR 0x23f0 — **MAPPED** регистр (device-unlock FW:
   единственный доступ — read, чек `== 0xbadc0ffe`; наш 0xbadc0001 →
   «locked» → поведение FW byte-identical исходному 0x0).
4. **Burn:** FNP + `--nofs --ignore_dev_data`; non-FNP failsafe-burn
   patched-образа отклоняется device-side MCC (digest) — итоги burn-циклов
   v1–v5 (вкл. урок relocation .ini) —
   `docs/750-exp/175-irisc-injection-burns.md`, рецепт —
   `docs/850-howto/190-irisc-build-burn.md`.

## 1. Цель и разграничение со «стеной» чтения

- Цель — **arbitrary code execution на CX-5 iRISC** + **host-видимый канал
  результата**. Канал через **host-CR регистр**, а не command-response
  0x0932 / MTRC-trace: оба последних закрыты на Production FW (таблица
  ниже; журнал 2026-09-21 §5).
- «Стена» (прежние выводы о чтении iRISC с хоста на Production FW) —
  **в силе**: касается **чтения** iRISC data-base / MTRC. **Исполнение**
  кода на iRISC через boot-patch и **вывод** результата через host-CR —
  работают. Разница в механизме: запись в CR делает **сам iRISC-код на
  boot** (внутри FW), а хост лишь читает обычный CR-регистр через штатный
  VSEC-интерфейс (доступен на Production FW; закрыт только MTRC
  control-plane).

| путь | статус | примечание |
|---|---|---|
| Чтение iRISC data-base / RAM с хоста (ExecShellcode64 0x0932, MTRC-trace, CR-space) | **закрыт** | Production FW: ExecShellcode64 → `0x1C2B78` (даже тривиальный probe — журнал 2026-09-21 §5.3), MTRC control-plane → 0x6C64FE/0xB63790; отдельного MTRC «IRISC-space» не существует (enum spaces — журнал 2026-09-21 §5.1) |
| FNP | **no-interface для чтения** — но **проверенный burn-путь** | в FNP нет VSEC → host CR не прочитать (журнал 2026-09-21 §7.2); FNP-burn patched-образа успешен многократно (v1/v2/v3/v5 — `750-exp/175`) |
| **Исполнение iRISC-кода (boot-patch) + чтение результата в host CR** | **РАБОТАЕТ** | маркер 0xbadc0001 в CR 0x23f0 прочитан с хоста (журнал 2026-09-21 §12) |

Железо/образ: `CARD_CX5_EDR100` (жертвенная; 81:00.0; до экспериментов —
FW 16.19.1200, PSID MT_0000000008). Целевой образ — STOCK CDA-4030
`refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin`
(md5 `a8c60c90473078288b01009c7cad471b`; MAIN_CODE byte-identical к
OCP-варианту синдиката — журнал 2026-09-20 §1).

## 2. Точка инъекции (MAIN_CODE 0x03, dc 0x1d594)

ITOC @0x5000, entry 0x03 (MAIN_CODE): size `0x3d15a0`, `clcrc=1`,
flash-addr `0x1c748`, **param0 (load base) = 0x800000**, **param1 (RAM-abs
entry) = 0x81d58c** → **entry = dc 0x1d58c** (dc = section-relative code
offset; dc == Ghidra-адрес при import с base=0x0; dc↔rt-конвенция —
`005-endian-addressing.md` §2). Кросс-чек на всех boot-секциях
(POST_IRON/IRON_PREP/PCIE_LINK/MAIN_CODE): одинаковый entry-паттерн
`call sp_init; st.d!; call main; jump next` (журнал 2026-09-20 §27.1).

Реальный entry-пролог (Ghidra-верифицировано; журнал 2026-09-20 §27.1–27.2):

```
0x01d588  addi zero,zero,0x0      ; (NOP)
0x01d58c  call 0x0001a4e4         ; SP init (r1 = (cpuinfo&0xf)<<13 + 0x7d1ff8) — всегда ret.d
0x01d590  st.d! r1,zero,-0x8      ; stack setup
0x01d594  call 0x0001e10c         ; main init  (НА boot-path НЕ возвращается)
0x01d598  jump 0x0001d598         ; SELF-JUMP (0x95000000) — МЁРТВЫЙ КОД
0x01d59c  csr.r r5,cpuinfo        ; cpuinfo-блок
...
```

- **dc 0x1d594** — 3-я инструкция entry, прямая цепочка после SP-init и
  stack setup; до неё нет условий → **исполняется на каждом boot**. Orig
  word = `0x940002de` (`call 0x1e10c`) (журнал 2026-09-20 §27.5).
- **dc 0x1d598 — dead code:** word = `0x95000000` = `jump (PC+0*4)` —
  прыжок на себя. Доказательство, что `0x1e10c` (main init) на boot-path
  **не возвращается**: вернись он — self-jump зациклил бы CPU; карта
  грузится healthy → цикла нет → всё после 0x1d594 (включая 0x1d598) на
  boot-path **не исполняется**. Детур v1/v2 стоял именно на этой мёртвой
  self-jump — потому молча не работал (журнал 2026-09-20 §27.3; вердикт H1 —
  журнал 2026-09-21 §10.6).
- **Декодер-факт:** iRISC call/jump target = **`PC + rel24*4`** (НЕ
  `(PC+4) + rel24*4`) — баг ручного декодера v1/v2-скриптов, исправлен
  после v2 (журнал 2026-09-20 §27.4). Подтверждено Ghidra: @0x1d594
  `0x940002de` → 0x1d594 + 0x2de*4 = 0x1e10c ✓; @0x1d58c → 0x1a4e4 ✓.
  Канонический декодер сегодня — `015-decoders.md`.

## 3. Патч (7 слов)

Инъекция **dc 0x1d594**: `0x940002de` → **`0x940dc067`** (`call 0x38d730`,
rel24 = 0xdc067, в signed24). dc 0x1d598 НЕ тронут (stock self-jump).

Шеллкод **dc 0x38d730..0x38d744** (6 слов; free-регион 0x38d730..0x38dbe9
all-zero до патча, assert; не цель никакого jump/call):

| dc | word | decode | смысл |
|---|---|---|---|
| 0x38d730 | `0x24050000` | `set2 r5,zero,0x0000` | r5 = 0x00000000 |
| 0x38d734 | `0x20a523f0` | `set3 r5,r5,0x23f0` | r5 = 0x000023f0 (CR 0x23f0) |
| 0x38d738 | `0x2406badc` | `set2 r6,zero,0xbadc` | r6 = 0xbadc0000 |
| 0x38d73c | `0x20c60001` | `set3 r6,r6,0x0001` | r6 = 0xbadc0001 (marker) |
| 0x38d740 | `0x6ca03002` | `st.d r6,r5,0x0` | [RAM 0x23f0] = [CR 0x23f0] = 0xbadc0001 |
| 0x38d744 | `0x95f24272` | `jump 0x1e10c` | resume main init |

Регистры: **r5/r6 — scratch** (caller-saved; эпилог main init их НЕ
восстанавливает), **r1 (SP)/r3 (context)/r4/r23 сохраняются** (main init
читает их в prologue). Все 7 слов decode-верифицированы; end-to-end в
Ghidra: `0x01d594 call 0x0038d730` (UNCONDITIONAL_CALL), шеллкод
декодируется ровно как задумано, `0x038d744 jump 0x0001e10c` (журнал
2026-09-20 §27.5–27.6; слова verbatim в §28.1). Прецедент-тест —
`tests/test_irisc_asm.py`.

## 4. Канал результата (host CR 0x23f0 через VSEC)

### 4.1 Чтение (журнал 2026-09-21 §9–§10, §12.2)

VSEC на CX-5 — **standard** vendor-specific capability **ID 0x09** (не
extended cap!), ищется обходом standard caps от `0x34`; на 81:00.0
**base = 0xc0** (Len 0x18). Offsets (из `refs/src/mstflint`
`mtcr_ul/mtcr_ul_com.c`, base+): CTRL `0xc4`(+0x04), COUNTER `0xc8`(+0x08),
SEMAPHORE `0xcc`(+0x0c), ADDR `0xd0`(+0x10), DATA `0xd4`(+0x14). Baseline:
CTRL=0x20000000, COUNTER=0x0, SEMAPHORE=0x0, ADDR=0x80000000, DATA=0x00000002.

Чтение (spec mstflint `mtcr_pciconf_mem_read`; точные команды):

```
setpci -s <dev> 0xc4.l=20000002   # CTRL: space=CR(0x2) в low16, upper 0x2000 сохранён
setpci -s <dev> 0xd0.l=000023f0   # ADDR: запрос чтения CR 0x23f0
setpci -s <dev> 0xd0.l            # poll ADDR bit31 → 0x800023f0 (READY)
setpci -s <dev> 0xd4.l            # DATA → 0xbadc0001 (patched3) / 0x0 (v1/v2/stock)
```

Read path **валидирован**: layout 1:1 с `mtcr_ul_com.c`, значения
стабильны (3–4 повторения), разные offset'ы → разные реальные значения
(0x0000=0x01002000, 0x23f4=0x40000, 0x23f8=0x039f6adb…), COUNTER
инкрементируется → чтение возвращает истинное содержимое, не константу
(журнал 2026-09-21 §10, §10.3).

### 4.2 Маппинг CR ↔ RAM ↔ regspace

Конвенция offset↔RAM↔regspace (включая unmapped-дефолт) —
`005-endian-addressing.md` §3, канон `irisc-asm`. Направление
iRISC→host было архитектурным выводом — **подтверждено этим PoC
экспериментально** (маркер записан iRISC-кодом, прочитан хостом; журнал
2026-09-20 §21, 2026-09-21 §12). Опоры: FW-инструкция `ld.i r6,0x8fc` →
RAM[4·0x8fc] = RAM[0x23f0] сверяется с 0xbadc0ffe (хост пишет CR 0x23f0 =
unlock, syndicate regdump) — тот же offset; `ld.i r21,0x8e89` →
RAM[0x23A24] = clkcnthi (slaspec-блок 0x63a20 = 0x40000+0x23A20).

### 4.3 Почему CR 0x23f0 (mapped, «locked»-безопасен)

- CR 0x23f0 = word-idx **0x8fc** = **MAPPED** регистр — device-unlock FW.
  Единственный доступ к нему во всём MAIN_CODE — **read** `ld.i r6l,0x8fc`
  @0x1076f8 в `FUN_001076f0`: сборка `0xbadc0ffe`, `subs`, чек ровно
  `r6 == 0xbadc0ffe`; не равно → ret `0xbadc0000` («locked»), равно → ret 0
  («unlocked»). Вызывается из 30+ мест **после** точки инъекции.
- Маркер `0xbadc0001 ≠ 0xbadc0ffe` → «locked» — **то же самое**, что
  исходное 0x0 («locked»); возврат функции идентичен в обоих случаях →
  **поведение FW byte-identical** (журнал 2026-09-20 §25.3).
- **FW не пишет в 0x23f0** (скан: 0× st.i→0x8fc, 0× base-zero store→0x23f0,
  0× csr.w→0x423f0; всего 202× st.i в FW, макс. target 0x572) → маркер не
  затрётся после boot (журнал 2026-09-20 §21, §25.3).

### 4.4 Почему НЕ другие адреса

- **Записи iRISC-RAM в unmapped-слоты отбрасываются (no-op).**
  Свидетельство: host CR 0x223f0 возвращает дефолт unmapped-слота `0x88fc`
  (= off/4, word index), а соседний mapped-слот 0x23f4 несёт реальные
  0x40000 (журнал 2026-09-21 §5.5, §10.3). v1 писал в 0x223f0 → маркера
  нигде не оказалось.
- **Чтение iRISC RAM с хоста (ExecShellcode64, mlx5 admin cmd 0x0932,
  через VFIO) — firmware-gated на Production FW** (MGIR life_cycle=0 /
  Production, debug=0, signed_fw=0): отклонение `BadParameter 0x1C2B78`
  **даже на тривиальном probe** (отказ на уровне команды/entitlement, не
  адреса — журнал 2026-09-21 §5.3/§5.5). MTRC-trace — тот же
  entitlement-lock. → прямой путь «хост читает iRISC RAM» закрыт;
  результат обязан выходить **в host-CR регистр, который пишет сам
  iRISC-код**.
- **Достигаемость CR 0x23f0 (word-idx 0x8fc):** до него дотягивается
  **только `st.d`-absolute** (base+off14; base из set2/set3):
  - `st.i` — imm11 ≤ 0x7ff → RAM ≤ 0x1ffc; 0x8fc > 0x7ff — **не достаёт**;
  - `csr.w.00` — regspace = 0x40000+4·imm11 ≤ 0x41ffe; 0x423f0 — **вне**;
  - `st.d`/`st.w`/`st.q` absolute — **единственный путь** (75120 abs-store
    в FW; подтверждено live: st.d в 0x223f0 дошёл до unmapped-слота —
    адресация идентичная) (журнал 2026-09-20 §25.1–25.2).
  - Баг-предостережение: 4-словой draft `st.i r3,0x8fc` — брак, imm11=0x8fc
    не кодируется, HW прочитал бы idx 0x0fc (журнал 2026-09-20 §25.2).

## 5. Состояние карты (итог, 2026-09-21)

- **`CARD_CX5_EDR100` (81:00.0) работает на patched5** (16.35.4030, PSID
  MT_0000000013; до экспериментов — 16.19.1200 / MT_0000000008):
  `15b3:1019` [ConnectX-5 Ex], mlx5_core bound, порт 0 UP, PCIe 16GT/s
  x16, dmesg без assert/recover (журнал 2026-09-21 §16). Карта healthy:
  шеллкод (clobber r5/r6 + resume-jump 0x1e10c) boot НЕ сломал;
  **маркер CR 0x23f0 = 0xbadc0001 (3× стабильно)**.
- **Base GUID/MAC в образе (patched5, из DTOC 0xE1/0xE0):** реестр
  `CARD_CX5_EDR100_GUID`/`CARD_CX5_EDR100_MAC` — в `mstflint q` не N/A
  (device-data из DTOC), netdev MAC порта 0 = Base MAC; **`sg` НЕ
  понадобился** (в отличие от v3, где `--ignore_dev_data` → N/A —
  `750-exp/175` §1) (журнал 2026-09-21 §16).
- **Коммент в .ini (patched5):** 1 строка о PoC (дата 2026-09-21, шеллкод
  @ dc 0x38d730 → host CR 0x23f0 = 0xbadc0001) — виден в `mstflint dc`.
- **Бэкап исходного состояния**: `root-mellanox:/root/backup-81-00-0-20260921.bin`
  (16.19.1200 + реальные GUID/MAC карты) — rollback; fallback — stock
  CDA-4030 (md5 `a8c60c90…`).

## Постулаты / открытое

- **64-bit `st.d` vs 32-bit эффект** — открытое (на вердикт не влияет):
  host-видимый эффект store оказался 32-битным — верхняя половина (0x23f4)
  **не затёрта** (0x40000, исходное), хотя маркер в 0x23f0 есть. Либо
  верхняя половина не легла в 0x23f4, либо FW переписал 0x23f4 после boot
  (это live mapped-слот; статскан покрывал только 0x23f0) (журнал
  2026-09-21 §12.3).
- **Дефолт unmapped-слота = off/4** `[факт]`: CR 0x23a24 → 0x8e89,
  CR 0x223f0 → 0x88fc — ломает простую модель identity «CR X ↔ RAM[X]»
  для **unmapped** слотов; identity подтверждена для mapped (журнал
  2026-09-21 §10).
- **Принуждает ли boot ROM сигнатуру на других SKU/secure-картах** —
  открытое: SIG_256/SIG_512/PUB_KEYS секции в образе есть, но ROM принял
  patched-образ (boot OK, patched-FW работает) на ЭТОЙ карте (риск журнала
  2026-09-20 §23/§24 → факт 2026-09-21 §8/§11); см.
  `docs/850-howto/170-signing-practical.md`.
- **Lock'и на patched FW в силе** `[факт]`: MGIR life_cycle=0 (Production),
  debug=0, signed_fw=0, sec_boot=0 (журнал 2026-09-21 §5.3 Run A) → MTRC
  control-plane и ExecShellcode64 по-прежнему отклоняются; работает только
  boot-patch-путь.
- **Переносимость не проверена** — открытое: PoC на MT28800 (CDA-4030,
  FW 16.35.4030). Работает ли та же точка/механика на других SKU/FW (в т.ч.
  8008 / MT27800, карта 01:00.x) — **не верифицировано**.
- **Чтение в FNP невозможно** `[факт]`: в recovery-режиме нет VSEC (журнал
  2026-09-21 §7.2) → маркер читается только после снятия strap +
  нормального boot.
- **Молчаливый relocation `.ini` = corruption (урок v4)** — закрыто
  2026-10-31 (цикл repack-burn-safety): рост packed-размера секции 0x30
  сверх `e.size` релоцирует её в tail-gap и стирает старое место →
  sector-revisit при FNP-burn уничтожает только что записанную INI и хвост
  ROM_CODE; два независимых триггера роста (коммент в .ini; 4-байтный
  zlib-drift zlib-ng). Фикс: packed ≤ original. Гейты mlxfwutil (verify FAIL
  burn-order, предзаписной отказ rc 2, safe-relocation, автознак 0xA0) —
  `docs/250-re/100-formats/050-fs4-burn-order.md` §3; механика и live-L2 —
  `docs/750-exp/175-irisc-injection-burns.md` §4.
