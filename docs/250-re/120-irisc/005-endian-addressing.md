# 005. Эндианность и адресация iRISC

> Источник: журналы
> `docs/superpowers/journal/2026-09-22-irisc-ondemand-s1-dispatcher-re.md`,
> `docs/superpowers/journal/2026-09-23-irisc-isa-i2b-rosetta.md`
> (SHA-256 Rosetta), `docs/superpowers/journal/2026-09-23-irisc-isa-fuzz-task-08.md`;
> консолидация цикла I5 (2026-10-05); конвенции канона — скилл `irisc-asm`
> (`scripts/irisc/README.md`); база cx6dx — журнал
> `docs/superpowers/journal/2026-10-30-cx6dx-securefw-task-02.md`.
> Связи: ISA-семантики → `010-isa.md`; декодеры → `015-decoders.md`;
> Ghidra-пайплайн/slaspec → `020-ghidra-pipeline.md`; dc↔rt-калибровка FS4 —
> `docs/250-re/100-formats/045-fs4-dc-rt.md`.

Критичные факты адресации iRISC (файл ↔ память ↔ runtime) и охват
irisc-кластера: установленные семантики ISA (`010-isa.md`), канонические
декодеры и их баг-фиксы (`015-decoders.md`), Ghidra-пайплайн и
slaspec-канон (`020-ghidra-pipeline.md`). Конвенции слов (BE, dc↔rt,
CR-маппинг, clcrc-фрейминг) канонизированы скиллом `irisc-asm`; этот
аспект — их фактическая база.

## 1. Слова iRISC в flash-файле — BIG-ENDIAN

**iRISC-слова в flash-файле — BIG-ENDIAN** (`struct.unpack_from('>I')`;
`scripts/irisc/irisc_dis.py:152`). LE-чтение даёт byte-swap + ложные
jump-targets (журнал S1-dispatcher, «S1 real root-cause RE» §2: читая как
LE, получался byte-swap и ложные jump-targets — отсюда «hook → 0x38d748» /
stub-jump «S+0x18»; правильно `u32 = unpack_from('>I')`).

Три подтверждения:

1. build-скрипты пишут BE (`be32()/u32()` в `build_s1*.py`);
2. mstflint verify PASS на BE-образах — mstflint знает формат (журнал S1,
   «Build: S1 redesign image (2026-09-23)»: «mstflint verify: PASS
   (bootable)»);
3. BE-декод даёт корректные инструкции (jump-targets, прологи).

Влияние: все ранние LE-декоды S1 (T1/T2/root-cause) — byte-swapped
(jump-target 0x38d748→0x38d750); op-check (0x0932, `[D+0x28]>>16`) —
**не** затронут (значение opcode то же, `>>16` верно для BE).

Исключение — секция 0x18 (ROM_CODE): там x86/arm64-код (FlexBoot PCI
option ROM + EFI-суб-образы) — little-endian; BE-конвенция — про
iRISC-секции ITOC (0x02..0x15) —
`docs/250-re/100-formats/020-fs3-sections.md`.

## 2. dc ↔ rt: runtime base по поколениям

Load base MAIN_CODE — по поколению, из профиля (`load_base`,
`scripts/irisc/profiles/`) или ITOC param0 секции 0x03:

| Поколение | base (rt = dc + base) | Опоры |
|---|---|---|
| cx5 / cx4lx | **0x800000** (пример: dc 0x38d730 ↔ rt 0xb8d730) | журнал i2b §2: константа K-таблицы материализуется ровно один раз (`002b1478 addi r3,zero,0x40a8` + `002b147c addi.hi r27,r3,0xb9` → r27 = 0xb940a8); «0xb940a8 − 0x3940a8 = 0x800000 ⇒ image runtime base = 0x800000»; полный addr = base 0x800000 + dc-офсет (журнал S1 §2); файл 3767744 B, BE32, 4-aligned; указатели в данных — runtime-адреса (таблица 0xab55d0) |
| cx6dx | **0x21000000** | 22.50.1002, верифицировано консенсусом пар addi/addi.hi 98.8% (журнал 2026-10-30-cx6dx-securefw-task-02); профиль `scripts/irisc/profiles/cx6dx.json` |

## 3. Эндианность памяти и CR-маппинг

- **Память — big-endian** для lw.r/ld.d/st.d/ld.q/st.q; ld.b/st.b — байты
  (алгоритмически верифицировано SHA-256-эмуляцией, журнал i2b §3–§5).
- **Host-CR ↔ RAM ↔ regspace:** offset X ↔ iRISC RAM[X] ↔ regspace
  0x40000+X (mapped-слоты; unmapped-дефолт = off/4) — конвенция канона
  `irisc-asm` (live-proven).
- **68B-фрейминг clcrc=1-секций:** строка = 64B код + 2B ноль-пад + 2B LE
  u16 clcrc (CRC-область 66B); развёртывание — только
  `clcrc_unwrap`/`clcrc_wrap` (`scripts/irisc/README.md`).

## Постулаты / открытое

- **Эндианность iRISC-CPU (vs файла)** `[постулат]`: BE файла доказан,
  прямое соответствие CPU не зафиксировано.
- **Byte order live-read через VSEC** `[постулат]`: хост x86 LE — маппинг
  байт-порядка live-читок не установлен.
