# 040. FS4: сигнатуры секций, домены исполнения, бут-цепочка

> Источник: офлайн-RE 2026-09-20, 9 образов `refs/fw/` (Ghidra
> iRISC:BE:32 + Python-пробники `scripts/probes/section_meta_probe.py`,
> `scripts/probes/iron_boot_probe.py`; уточнение ROM_CODE 2026-09-28).
> Журналы: `docs/superpowers/journal/2026-09-20-fw-toc-section-sig.md`,
> `2026-09-20-fw-iron-boot-chain.md` (полная таблица 7 секций × 7 образов
> — его §2.1), `2026-09-28-oprom-img2-unpack.md`.
> dc↔rt-калибровка MAIN_CODE — `045-fs4-dc-rt.md`.

## 1. Домены исполнения ITOC (верифицировано Ghidra + эвристика)

| группа | тип | домен |
|---|---|---|
| код ASIC | 0x02/0x03/0x04/0x05/0x06/0x07/0x0d/0x0e/0x15 | **iRISC** (все; x86/arm64 в ITOC нет). Эррата (corpus arc A, 2026-11-11): CX-6 20.43 §0x15 — data-dominant (инстанс-классификатор 0.150; size 0x4a00, param0=0, 3 код-островка ≈6.8% слов, без ASCII); CX-6Dx 22.50 §0x15 проходит (0.540). Первопричина: вердикт «(все)» обобщал CX-6Dx-наблюдение без пер-семейной верификации §0x15 (секция встречается только на CX-6/6Dx, §5). Семейный override приора: cx6/0x15 → данные (журнал `2026-11-11-serdes-corpus-a-task-09.md`). CCIR-семантика (arc B, 2026-11-12): 0x0d (8788 B) = event-loop/таймеры, 0x0e (15172 B) = rate-алгоритм `ztr_rttcc` — RoCE RTT-based congestion control (DCQCN/TIMELY-семейство: AIMD/CNP/NACK/RTT); поколенческая карта: есть у CX-6Dx 22.50, CX-6Lx 26.50 и CX-7 28.33 (предрелиз, n=2: ztr-маркеры `Nvidia ztr_rttcc` / `v0.5` — нумерация версий отличается от CX-6Dx v0.12/v0.13), нет у CX-4/5/6 non-Dx и A16; CC-IR = Congestion Control iRISC (гипотеза-бонус; `docs/superpowers/reports/serdes-arc-b.md`) |
| код ASIC | 0x0f FS4_BOOT3_CODE (новый, только CX-7 28.33-класс, предрелиз) | **iRISC** (честный вердикт, арка securefw-arc-a 2026-11-14: recount 0.97 у обеих версий; param0 0x20500040, entry=load+4 как PCI_CODE §3; ASCII-строк нет; журнал `2026-11-14-securefw-arc-a-task-03.md`; корпус: `DOMAIN_PRIOR_OVERRIDE[("cx7",0x0f)]="iRISC"` с 2026-11-14, решение владельца, мемо `2026-11-14-cx7-0x0f-domain-promotion.md` — дизасм-артефакты строятся) |
| APU | 0x14 APU_KERNEL (новый, только CX-7 28.33-класс, предрелиз) | **данные**: recount-мажорити iRISC 0.56–0.68 — ложный сигнал (как у PHY 0x0a); APU-ядро **RISC-V** (строки `src/kernel/arch/riscv_apu0/…`, `fw_rv_kernel`, clang `RISCV_LLVM` 12.0.0; внутри CC-алго `…/src/apu/progcc/algo/{dcqcn,ztr_rttcc,pcc_debug}.c`; param0=param1=0 — ITOC RAM map окно APU не описывает); журнал `2026-11-14-securefw-arc-a-task-03.md` |
| PHY | 0x0a PHY_UC_CODE, 0x0c PCIE_PHY_UC_CODE | **данные**: таблицы с шагом 16B (микрокод PHY, не код; iRISC-ratio 0.92–0.94 — ложный сигнал) |
| PHY | 0x0b PHY_UC_CONSTS | данные (zero) |
| ROM | 0x18 ROM_CODE | **x86**: FlexBoot — цепочка суб-образов PCI option ROM (по `55AA`+PCIR, длина @PCIR+0x10; CodeType: 0=legacy x86 plain, 3=EFI, ff=vendor): legacy 16-bit x86 (iPXE, `55AA`@0, plain) + EFI-суб-образы **standard-compressed** (арх читается офлайн — §2, ROM_CODE) |

## 2. Внутренние сигнатуры данных (AC-образ, FS4)

- 0x10 IMAGE_INFO: psid@0x24, dev(ven:dev)@0x1c (BE).
- 0xe0 MFG_INFO: psid@0x00. 0xe1 DEV_INFO: tag `mDevInfo#B`@0x00, magic
  `cafabacafe`@0x0a (у AC 2×0xe1: вторая — mostly-empty).
- 0x30 DBG_FW_INI / 0x32 DBG_FW_PARAMS / 0x33 FW_ADB — zlib (`78da`).
- 0x18 ROM_CODE, EFI-суб-образы (уточнено 2026-09-28): это **EFI PCI
  Expansion ROM Header** (EfiSignature `0x0EF1` @+0x04, machine @+0x0A —
  arch читается офлайн: `0x8664`=X64, `0xAA64`=ARM64; CompressionType=1
  @+0x0C, EfiImageHeaderOffset @+0x16) + поток **EFI 1.1 Tiano**
  (LZ77+Huffman, pbit=4; заголовок `{u32 comp, u32 orig}`). Распаковывает
  **серверный UEFI** (gEfiDecompressProtocol) при загрузке ROM — потому во
  флеше/`strings` plaintext отсутствует; офлайн распаковано (порт
  Tiano-декодера EDK2). Внутри — PE32+ драйвер `Mlx5Nodnic` (X64; у
  generic-билдов CX-5 есть и ARM64-дубль). Суб-образ CodeType=ff («img1»,
  существует со времён CX-2) — упаковка не Tiano/LZMA/zlib, не распакован
  (открытый вопрос; для UEFI-темы нерелевантен).
- 0xa0/0xa3: `signature_uuid`@0x00, `keypair_uuid`@0x10 (uuid-поля
  подписи — `docs/250-re/110-signing/015-key-sections.md`).
  AC (SB): 0xa0 erased(0xFF), 0xa3 keypair=`c55d54e8…`; 0xa6: 4B hdr +
  keypair@0x04 + RSA-4096@0x14; 0xa7: 3×512B sigs.
- DTOC vendor-cert секции (0xd0/0xf2–0xf7/0xed) — erased/zero:
  сертификатов в vendor-образе нет.

## 3. Бут-цепочка (только доказанное)

- Во всех 9 образах первая по флэш-адресу кодовая секция = **0x05
  IRON_PREP_CODE** (FS4 @0x7000, Dell-16.27 @0x5000, FS3 @0x4000); 0x01
  BOOT_CODE отсутствует везде.
- Единственная RAM map (load/entry) в образе — **ITOC** (param0/param1);
  jump-таблиц «секция→секция» нет (BE-скан 9 образов) — загрузчик
  (ROM/FlexBoot) читает ITOC и сам грузит/переходит.
- PCI_CODE: entry = load+4 у всех 9 образов.
- 0x05 → 0x06 (Ghidra, AC): entry 0x05 = диспетчер (`call prelude →
  main-init → halt`), строит адреса 0x20748951/0x2074D228 = страница
  POST_IRON; ~25 его вызовов уходят в 110KB-район [0x206F4610..0x2070F614]
  **ниже** load-базы, отсутствующий в образе («prelude» докладывается ROM)
  — главный открытый разрыв. 0x06 другие секции не адресует. Дальше
  (0x02→0x04→0x03) не доказано.
- RESET_INFO (0x20, 0x100B) — побайто идентичен во всех образах
  (sha256-префикс `7af41c9b`) — общий blob, не карт-специфичный.
- MAIN_CODE — clcrc=1 (64B+4B CRC) у всех 9 (FS3 и FS4); хеш MAIN в
  подписи считается по коду **без** line-CRC (de-clcrc-вид).

## 4. Размеры boot-секций (flash-size / load / entry-offset)

| секция | CX-6Dx AC 22.50 | CX-6 20.43 | CX-5 16.35 | CX-4 (FS3) |
|---|---|---|---|---|
| 0x05 IRON_PREP | 0x2d27c / 0x20710000 / +0x1cbd0 | 0x1c19c / 0x20710000 / +0x15524 | 0x15494 / 0x710000 / +0x616c | 0xe328 / 0x710000 / +0x2ac8 |
| 0x06 POST_IRON | 0xb50 / 0x20742200 / +0x318 | 0xa90 / 0x20740000 / +0x2fc | 0xb90 / 0x740000 / +0x2c0 | 0xe20 / 0x740000 / +0x254 |
| 0x02 PCI_CODE | 0x3a040 / 0x20520000 / +0x4 | 0x31f00 / 0x20530000 / +0x4 | 0x2e040 / 0x1000000 / +0x4 | 0x2ab38 / 0x500000 / +0x4 |
| 0x03 MAIN_CODE | 0x5c9a00→0x572787 / 0x21000000 / +0x2083c | 0x471070→0x42e24b / 0x21000000 / +0x1f61c | 0x3ccdf0→0x393a4b / 0x800000 / +0x1cf18 | 0x30a590→0x2dc900 / 0x800000 / +0x6bb8 |

## 5. Дискриминация карт (офлайн, из образа)

FS3/FS4, PSID (0x10/0xe0), dev (0x10@0x1c), FlexBoot-версия (ROM_CODE),
SB-набор (0xa3/0xa6/0xa7), набор секций (0x15 ACE_CODE — только CX-6/6Dx;
0x0d/0x0e CCIR — CX-6Dx, CX-6Lx 26.50 и CX-7 28.33 (§1); 0x0f/0x14 —
только CX-7 28.33-класс). Любая пара карт
различается по ≥3 независимым сигналам.
