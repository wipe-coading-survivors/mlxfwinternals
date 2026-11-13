# 020. Стена: следствия для фаз B–D (сжатие §5 фазы A)

> Источник: из 95 §5 (выводы фазы A «IB cable-speed gate», 2026-09-16/21;
> сжато при переносе 2026-11-07, закрытое помечено по состоянию на главу 3).
> Журналы — как в `010-wall.md`.
> Связи: цепочка → `005-chain.md`; полная карта тупиков → `010-wall.md`;
> итоги главы 3 и ретест 8008 → `025-ch3-results.md`; burn/FNP →
> `docs/850-howto/100-cross-flash-ops.md`.

1. **RE-объект подтверждён** (live msg == .bin @0x3DA6F4 — `005-chain.md`
   §3). Дальнейший RE — в base-образе 8008-ACA; будущие burn/patch — на
   as-found VPI iD (`010-wall.md` §10).
2. **Функция-гейт НЕ локализована** (вывод фазы A; стена `010-wall.md`).
   Кандидаты — 54 base-значения в 0x3DA208..0x3DA6A5; зона = speed-nego
   (`ib_speed_nego_fsm`/`ib_speed_nego`/`speed_and_width`); base-регистр —
   главный недостающий элемент (выставляется в init, значение «не в образе»).
   **Закрыто**: стена — артефакт метода (ретест 2026-10-15), цепочка
   локализована и на 8008 — `025-ch3-results.md` §7.
3. **Секция патча = MAIN_CODE 0x03** (при локализации). «Хендлер в другой
   секции» опровергнут — 0x02/0x0a/0x18 перебраны (`010-wall.md` §1).
4. **Динамическая отладка (чтение) iRISC на этой карте невозможна**
   (lifecycle=PRODUCTION(0), MTRC control-plane заперт, ExecShellcode
   отклонён, CR-space не даёт iRISC-flash, FNP=no-interface, DEV byte-flip
   не разблокирует MTRC — `010-wall.md` §5–§9). Любое снятие base «с живой
   карты» требует Mellanox-signed debug-entitled 8008-образа /
   lifecycle-change (entitlement-ключ) — за рамками read-only-дисциплины и
   без явного GO владельца. Альтернативы: offline-RE-rethink (реализовано
   главой 3) или transceiver fallback (IB-compatible SFP28 — исключено
   теоремой SFP28, `../100-formats/070-transceiver-eeprom.md` §3).
   ОБНОВЛЕНИЕ: запрет — про **чтение** iRISC с хоста; **исполнение**
   boot-patch-кода на iRISC + чтение результата через host CR 0x23f0 —
   работает (`../120-irisc/025-boot-injection.md`; верифицировано на
   `CARD_CX5_EDR100`, не на 01:00.x).
5. **Для фаз B–D (как поставлены фазой A):** (B) патч-кандидат ищется
   оффлайн в 0x03 по зоне + 54 base-кандидатам (log-каталог index 162 как
   якорь FDR10) — **закрыто ретестом** (инлайн-адресация; C12-аналог —
   `025-ch3-results.md` §7); (C) перенос в 1900 (Lx) — **логика**, не код
   (код 8008/1900 — 5.2% verbatim, разное силикон; спека R3); строки гейта
   1900 (sect-rel): HighBER 0x33efad, FDR10 0x33f034, CS 0x33f06c, NoIssue
   0x33f084; база — T3-образ CX-4Lx MCX4121A 14.32.1900 + VPI (сервер
   `/var/roothome/t3_cx4lx_ib.bin`); (D) live-валидация — только через PDDR
   (monitor_opcode/status_message), без shellcode/trace. Реализация фаз —
   глава 3 арки (retarget на 4030, `025-ch3-results.md`).
6. **Операционное правило (VPI-iD) и состояние карты** (`010-wall.md` §10):
   as-found 01:00.x (`CARD_CX5_25G`) = VPI-образ iD
   (`build/sfp28_iD_acat8008_vpi.bin`, md5
   `db32b31829a984f781fda1402c796012`); любой burn сбрасывает VPI (01:00.1
   IB→EN). Любая будущая burn — только iD + IPMI reboot + проверка `[0207]`
   / `LINK_TYPE_P2=IB(1)`. Карта возвращена в as-found: 01:00.0 ETH UP
   (vlan0071), 01:00.1 IB, FW 16.35.8008 / `MT_0000000080`, GUID/MAC intact
   (ярлык — `docs/050-hardware/100-inventory.md`), VPI active
   (`LINK_TYPE_P1=ETH(2)`, `LINK_TYPE_P2=IB(1)`), MGIR all 0, MTRC locked
   (`MTRC_CONF → 0x6C64FE`).
