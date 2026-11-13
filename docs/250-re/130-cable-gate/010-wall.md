# 010. Стена фазы A: полная карта тупиков (чтобы не повторять)

> Источник: из 95 §3 (фаза A «IB cable-speed gate», 2026-09-16/21; ретест
> 2026-10-15). Журналы:
> `docs/superpowers/journal/2026-09-16-ib-cable-gate-re{2,3,4}.md`
> (стена/ISA/ITOC), `…-ib-cable-gate-live-mtcr.md` (Task 3L),
> `…-ib-cable-gate-fnp-probe.md` (checkpoint 8),
> `…-ib-cable-gate-dev-burn.md` (DEV byte-flip),
> `2026-09-13-sfp28-vpi.md` (VPI-iD),
> `2026-10-15-8008-wall-retest.md` (ретест).
> Связи: цепочка симптома → `005-chain.md`; итоги главы 3 и ретест-цепочка
> 8008 → `025-ch3-results.md`; исполнение iRISC через boot-patch →
> `../120-irisc/025-boot-injection.md`; burn-циклы FNP →
> `docs/750-exp/175-irisc-injection-burns.md`; ISA-полный справочник →
> `../120-irisc/010-isa.md`.

**SUPERSEDE 2026-10-15 (ретест, журнал `2026-10-15-8008-wall-retest.md`):
§3-«стена» = артефакт метода фазы A, снята.** Три ошибки фазы A: (1)
проигнорирован clcrc=1 — MAIN_CODE framed 68B-линиями, runtime = dc
(де-фрейм), а искали lo16(raw); (2) ITOC addr=0x1c748 (flash-офсет секции,
`flash_addr` в mstflint) трактован как load-адрес — реальный load base =
**param0 = 0x800000** (тот же ITOC-entry, mlxfwutil RAM map); (3) addi.hi
гистограммировали только в окне imm16 0x0030..0x0050, а реальных hi строк =
0xB4..0xB9. Полный скан по dc-блобу: **8486 addi+addi.hi пар, 8463 (99.7%)
строят адресы в [0x800000, 0xB98988), 6455 — ровно на начала строк**;
строки гейта адресуются инлайн. Выводы §1 ниже («все рефы через data-base»,
«значение не в образе», «54 кандидата») — закрыты ретестом; историческая
карта сохранена как хроника и как карта тупиков live/FNP/DEV (те в силе).

**SUPERSEDE 2026-09-21 (boot-injection, `../120-irisc/025-boot-injection.md`):
«отклонены/заперто» ниже — про ЧТЕНИЕ iRISC data-base / MTRC control-plane с
хоста на Production FW — результат в силе.** НОВОЕ: можно **исполнить**
впрыскнутый iRISC-код (firmware boot-patch, FNP-burn) и **прочитать его
вывод** через host-CR регистр (CR 0x23f0, VSEC space=CR(0x2)) — PoC
подтверждён на жертвенной карте `CARD_CX5_EDR100` (81:00.0, MT28800, FW
16.35.4030): маркер 0xbadc0001. FNP — проверенный burn-путь (3× успех;
`docs/750-exp/175-irisc-injection-burns.md`).

## 1. Оффлайн-стена (4 раунда, 18 ITOC-секций; закрыта ретестом)

- **«Все рефы на строки — через data-base регистр»** (вывод фазы A, закрыт
  ретестом): кандидатный
  диапазон base = **0x3DA208..0x3DA6A5** (pool-adjacent); base выставляется в
  init; значение «НЕ в образе»: для 692 чистых Ghidra-оффсетов MAIN_CODE
  найдено 54 кандидатные base, ни одна не встречается как 32-битное слово,
  set-пара, set2/addi.hi → «статически невосстановимо». (Ретест: base =
  0x800000, и он в образе — шапка-JSON выше.)
- **«Хендлер в другой секции» опровергнуто.** Whole-image скан (режим
  `--mode build`): ни одна из **18** ITOC-секций НЕ строит адреса 4 строк
  (pointers / set-pairs / build-pairs / own-pool / base+offset — все 0).
  0x02/0x0a/0x18 чистые; строки и зона гейта — в MAIN_CODE 0x03.
- **Секция патча = MAIN_CODE 0x03** (при локализации; план не
  перенацеливать).

## 2. ISA-факты (верифицировано, re3 — iRISC.sla + Ghidra + refs/src)

- **Регистры:** r0(zero)..r31 (64-bit) + rXl/rXh (32-битные половины) + CSR
  (0x40000+) + pc/CmpA/CmpB (0x80000) + флаги (0x81000). **DP/data-pointer/
  segment-base регистра НЕТ** → «база данных» — обычный регистр, загружаемый
  в init из CSR/hardware.
- **Addressing:** `ld.d/st.d` (op 0x19/0x1b) = `RS + OFF14` (signed ×4,
  ±32KB, word-align); `ld.b/st.b` (op 0x18/0x1a) = `RS + simm16` (byte,
  ±32KB); `lw.r` (op 0x3f) = `*[ram]:4 (RS + RT)` (base + REG-offset).
  **DP/segment-relative режима НЕТ** (base — любой регистр).
- **Сборка адресов:** `set0/set1/set2/set3` = op 0x06/0x07/0x09/0x08;
  `word = (op<<26)|(RS<<21)|(RD<<16)|imm16` (set2 → биты 16..31, set3 → биты
  0..15). `addi.hi` (op 0x02/0x03) в коде на 0x3b «отсутствует» (фаза A
  искала не в том окне imm16 — см. шапку).
- **call/jump** = op 0x25, **REL24** (PC + 4×simm24).
- **Адресное пространство 30-bit** (0x0..0x3fffffff; bit31 = R/W;
  `mtcr.rs`: `address & 0x3fffffff | (1<<31)`).
- **Ghidra refsTo** — только PC-relative (call/branch); base+offset
  data-ссылки → const-space оффсет (refsTo=0 на данных — ограничение
  инструмента, НЕ доказательство «не используется»).

## 3. ITOC-карта (re4, mlxfwutil.py)

| секция | имя | size | iRISC_abs | end |
|---|---|---|---|---|
| 0x02 | PCI_CODE | 0x02e140 | 0x004031c8 | 0x00431308 |
| 0x0a | PHY_UC_CODE | 0x009920 | 0x00432fc8 | 0x0043c8e8 |
| 0x18 | ROM_CODE | 0x06fc28 | 0x00445078 | 0x004b4ca0 |
| 0x03 | MAIN_CODE | 0x3d2220 | 0x0001c748 | 0x003ee968 |

0x0a PHY_UC — не iRISC (82% слов op 0x00, ld.b=0); 0x18 ROM — PCIR (магия
`PCIR` на +0x1c). PCI_CODE (base 0x4031c8) — единственная из 3 в пределах
OFF14-охвата от строк (−0x48B4 ≈ 18KB), но рефов 0. Ретест-уточнение:
0x1c748 = `flash_addr` (офсет во flash); load base = `param0` = 0x800000
(`cibfw_layouts.h`; `025-ch3-results.md` §7).

## 4. iRISC-память ≠ file-offsets .bin

- `.bin[0:4] = 0x4d544657` («MTFW» — FS4-магия), но live `mstmread 0x0 =
  0x01002000` → iRISC-память **НЕ** маппится 1:1 на file offset.
- Карта CR-пространства (mstmread 01:00.1): 0x0=0x01002000, 0x1c748=0x000071d2,
  0x100000=0x24020000 (реестры, реал); **0x200000 и 0x3DA000+ → единый
  sentinel 0x00010000** (закрыто/unmapped); 0x400000/0x800000/
  0x1000000..0x38000000 → 0x0.
- Сигнатура 0x30F0014 = 0x0 (не 0xbad0cafe → не secure-host mode).
  Flash-магия «MTFW» в CR-space не найдена → **iRISC-flash (и base в нём) не
  достижим через mstmread (CR-space по BDF)**.

## 5. Live (3 пути — все отклонены; карта as found после каждого)

- **(A) ExecShellcode без trace** → `BadParameter, syndrome 1846136`
  (**0x1C2B78**). badc0ffe@0x23f0 unlock **активен**
  (check_badc0ffe_unlocked=true) — **НЕ enabler** (отклонён с активным
  unlock). 3 окна: окно 1 — bind ENODEV (без `new_id`); окно 2 —
  `run-shellcode` (без pre-setup); окно 3 — `regdump` + unlock (активен) →
  тот же синдром.
- **(B) MTRC arm** (playground-последовательность): badc0ffe unlock +
  set_itrace + **AllocPD pd=16 + mkey 0x40042 OK** →
  `MtrcCapReg{trace_owner=1}` @ 0x9040 → **«Bad system State», syndrome
  0x6C64FE (7103742)** (HCA post init=true, ISSI=1). Trace НЕ армирован →
  к ExecShellcode НЕ дошли.
- **(C) mstmread / VCR config-space** (cap 0x09): читает chip-registers;
  0x0–0x1FFFF → iRISC-память **не в этом пространстве** (sentinel
  0x00010000).

## 6. Права (решающе; entitlement-чек checkpoint 7, read-only)

- **Lifecycle = PRODUCTION(0):** MGIR (0x9050) `life_cycle=0, msb=0`
  (FS4_LC_PRODUCTION=0), `debug=0 dev=0 secured=0 signed_fw=0 sec_boot=0`;
  `mstflint q` — «Security Attributes: N/A» (= не secure-fw и не signed-fw).
- **MTRC-функция В FW:** `MTRC_CAP` (0x9040) read **OK** — `trc_ver=1,
  trace_to_memory=1, log_max_trace_buffer_size=0x13` (2^19=512KB),
  `num_string_db=2`, 2 string-DB (0xb46dc0/0x4f6c0, 0x103b200/0x3800);
  `MTRC_STDB` (0x9042) read OK.
- **Control-plane ЗАПЕРТ:** `MTRC_CONF` (0x9041) read → `ICMD 0x6C64FE`;
  `MTRC_CTRL` (0x9043) read → `ICMD 0xB63790`; `MTRC_CAP` **write**
  (trace_owner) → `0x6C64FE`. Синдром 0x6C64FE воспроизведён **двумя
  независимыми инструментами** (mlx5cmd/VFIO window 4 + mstreg).
- **Enabler НЕ найден:** HCA cap-битов нет (HCA_EXT 0x5011 → `ICMD
  0x6C4D48`, недоступен); mstconfig — ни одного MTRC/trace/debug-параметра.
- **Вывод:** MTRC-функция в бинаре есть, но её управление (owner/CONF/CTRL)
  FW отклоняет в PRODUCTION + non-debug состоянии. Единственный enabler =
  **lifecycle-change** (PRODUCTION → Pre-Production/Development) **или
  debug-entitled FW** — оба требуют Mellanox-signed image + entitlement-ключ
  (локально недоступен). **Динамическая отладка iRISC (чтение) на этой
  карте невозможна в принципе.**

## 7. Итог стены

| слой | статус |
|---|---|
| Оффлайн (18 секций) | base-регистр из init, значение не в образе (54 канд.) — **стена** [снята ретестом 2026-10-15] |
| Live (A/B/C) | ExecShellcode 0x1C2B78 / MTRC 0x6C64FE / CR-space — **отклонены** |
| Права (lifecycle) | PRODUCTION(0) + non-debug → MTRC control-plane **заперт** |
| FNP (checkpoint 8) | no-interface: ICMD absent, cr-sentinel 0xe633c3c7, no BAR0 — **отклонён** |
| DEV byte-flip | `debug_fw` bit13 → MGIR debug=0, MTRC locked 0x6C64FE/0xB63790 — **опровергнут** |
| **Результат** | base-value НЕ снят ни одним live/FNP/DEV-путём (чтение); остался только Mellanox-signed debug-entitled FW / offline-RE-rethink (реализовано гл. 3) / transceiver fallback |

## 8. FNP (checkpoint 8) — no-interface (не lock-bypass)

Гипотеза: в FNP production-образ 8008 не запущен (020d flash-recovery),
PRODUCTION-lock может не действовать → чтение r1..r31 даст base. **Исход:
FNP_NO_EXEC** — FNP не lock-free, а **no-interface** среда (для чтения;
burn-путь — см. шапку-SUPERSEDE).

- `mstreg` (MGIR/MTRC_CAP/MTRC_CONF/MTRC_CTRL/MTRC_STDB) → единственная
  ошибка: `-E- Failed to send access register: ICMD interface is not
  supported for this device` → MTCR/ICMD access-register interface в FNP
  отсутствует.
- cr-space (`mstmread 01:00.0`): `0x0=0x00000000`, `0x8=0x00000002`,
  `0x10=0x00000004`, `0x1c748=0x000071d2` (**== production**),
  `0x100000=0x20000000`, `0x180000..0x3DA700` (весь iRISC-code range) →
  единый sentinel `0xe633c3c7`, `0x400000+` → read hang. → iRISC-память в
  cr-space в FNP не читается (production-sentinel был `0x00010000`).
- Устройство 020d: driver отсутствует; **все 13 BAR = 0x0**; capabilities —
  только PM v2 + Express v1 Endpoint (нет HCA-BAR/mlx5 command queue).
- VFIO-микро-тест (владелец bound 01:00.0 → vfio-pci): BAR **не создаёт**
  (все 13 BAR по-прежнему 0x0); `regdump` под `timeout 45` → `Error: Bar0
  not found`, `EXIT_CODE=1` (FLR выполнен, host стабилен) → ExecShellcode
  невозможен.
- **Вывод:** base-регистр (r1..r31) в FNP не читается ни ICMD, ни cr-space,
  ни shellcode; FNP не де-рискит DEV-burn — он подтверждает тупик для
  iRISC-чтения.

## 9. DEV byte-flip (burn/MTRC/restore) — DISPROVEN

Гипотеза: byte-flip `debug_fw` (bit13 IMAGE_INFO DWORD[0]) в образе на
non-secure карте разблокирует MTRC control-plane → чтение data-base. **Исход:
MTRC НЕ разблокирован**; гейт = entitlement (signed debug token), не байт.

- DEV-образ `refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-DEV.bin` (sha256
  `3a1ac6235e98760320b6fc7062212ca6877211617a9cb7e897fd3ccb493eb4ca`)
  создан из original 8008-ACA (sha256
  `4296d2d585c1231c53e68904ec4ba3bd2cd0906ce77a9f31fa5190cae7dc5513`,
  интактен): ровно 5 байт.

  | offset | old | new | смысл |
  |---|---|---|---|
  | 0x43e769 | 0x03 | 0x23 | debug_fw (bit13 DWORD[0] IMAGE_INFO) |
  | 0x515a | 0x5c | 0xe0 | ITOC-entry sec_crc hi (0x5ce6 → 0xe04d) |
  | 0x515b | 0xe6 | 0x4d | ITOC-entry sec_crc lo |
  | 0x515e | 0xa9 | 0xef | ITOC-entry CRC hi (0xa920 → 0xefc6) |
  | 0x515f | 0x20 | 0xc6 | ITOC-entry CRC lo |

- Burn: `mstflint -d 01:00.0 -i /var/roothome/fw-8008-DEV.bin --no_fw_ctrl -y
  burn` → «Burning FW image without signatures - OK», EXIT=0; IPMI reboot.
  Карта НЕ brick (1017, FW 8008, port0 EN up); побочный эффект: 01:00.1
  IB→EN (§10 VPI).
- MTRC-тест после DEV-burn: MGIR `secured/signed_fw/debug/life_cycle/
  sec_boot/life_cycle_msb = 0` → byte-flip НЕ перевёл device в debug;
  `MTRC_CAP` (0x9040) read OK (как в production); `MTRC_CONF` (0x9041) →
  `ICMD 0x6C64FE`; `MTRC_CTRL` (0x9043) → `ICMD 0xB63790` (синдромы
  идентичны production); MTRC_CAP write не выполнялся, но control-plane уже
  locked по reads.
- Техническое примечание (source, `refs/src/mstflint`): `mstflint -i <image>
  q` не печатает Life-cycle (subcommands.cpp:4966, gated на
  device_specified); enum `FS4_LC` = PRODUCTION(0)/GA_SECURED(1)/
  GA_NON_SECURED(2)/RMA(3) — DEVELOPMENT **нет**. `life_cycle/debug/dev/
  secured/signed_fw` — RO-биты MGIR fw_info (`secured@0x0.24,
  signed_fw@0x0.25, debug@0x0.26, dev@0x0.27`, `life_cycle@0x34.0-1`). В
  образе (IMAGE_INFO DWORD[0]) enabler = `debug_fw` (bit13), `signed_fw`
  (bit14), `secure_fw` (bit15), `debug_fw_tokens_supported` (bit7), `mcc_en`
  (bit8). → для non-secure карты byte-flip `debug_fw` без подписанного
  токена device-state не меняет.
- **Вывод:** MTRC byte-flip гипотеза **ОПРОВЕРГНУТА**; чтение data-base
  через MTRC этим путём невозможно. Нужен Mellanox-signed debug-entitled
  8008-образ.

## 10. VPI-iD (операционное правило)

- **As-found 01:00.x (`CARD_CX5_25G`) — VPI-образ iD**, а не чистый 8008-ACA:
  `build/sfp28_iD_acat8008_vpi.bin` (md5
  `db32b31829a984f781fda1402c796012`) = 8008-ACA + GUID/MAC + байты VPI
  (`0x11+0x2bb=07` port1 def-IB, `0x11+0x2b7=0b` port0 def-ETH,
  `0x12+0x0f8=31`).
- В чистом 8008-ACA порты EN-locked (mstconfig `LINK_TYPE` отсутствует); в
  VPI-образе порты VPI-выбираемые (`LINK_TYPE_P1=ETH(2)`, `LINK_TYPE_P2=IB(1)`).
- Любая burn (DEV и чистый 8008-ACA) сбрасывает VPI: 01:00.1 IB→EN.
  Восстановление as-found = burn iD + IPMI reboot + проверка `[0207]` /
  `LINK_TYPE_P2=IB(1)`.
- Серверный mstconfig (кастомный mstflint 4.36.0 `f3a3dab`, /usr/local) без
  config DB; использован `mstconfig -b /var/roothome/mlxconfig_host.db` (DB
  скопирована с toolbx 4.36/`f3a3dab`, sha256 `de690d02…`; repo-DB 4.37.0 не
  подходит по версии).

## 11. Финальная карта live/FNP/DEV-путей к data-base (чтение)

| путь | результат | вывод |
|---|---|---|
| ExecShellcode (production, badc0ffe unlock) | `BadParameter 0x1C2B78` | unlock активен, но не enabler |
| MTRC-trace arm (production) | `MTRC_CONF/CTRL/CAP-write → 0x6C64FE/0xB63790` | entitlement-locked (PRODUCTION + non-debug) |
| VCR/mstmread CR-space | sentinel `0x00010000`, iRISC out of range | iRISC-память не в CR-space |
| FNP (020d) | ICMD not supported, cr-sentinel `0xe633c3c7`, no BAR0 | no-interface, base не читается |
| DEV byte-flip (`debug_fw` bit13) | MGIR `debug=0`, MTRC-синдромы как в production | не entitled; нужен signed debug token |
| **Остались** | Mellanox-signed debug-entitled 8008-образ; offline-RE-rethink (реализовано гл. 3 — `025-ch3-results.md`); transceiver fallback (IB-compatible SFP28 → закрыто теоремой SFP28, `../100-formats/070-transceiver-eeprom.md` §3) | без явного GO не шить/не трогать карту |

Исполнение (не чтение) iRISC-кода через boot-patch + вывод через host CR
0x23f0 — работает (`../120-irisc/025-boot-injection.md`; верифицировано на
`CARD_CX5_EDR100`, не на 01:00.x).
