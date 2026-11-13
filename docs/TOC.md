# docs/ TOC

## 010-roadmap — карты инициатив
- 100-irisc — iRISC-программа: ISA-RE, on-demand exec, детур CX-4 Lx, readback-каналы [done]
- 110-breakout — breakout (fan-out): больше GUIDов/портов, чем физических — исследование [seed]
- 120-mtusb-i2c — аналог MT-USB: out-of-band доступ через I2C (CH341/347) [seed]
- 130-ncsi-smbus — NC-SI + SMBus: out-of-band канал управления BMC ↔ карта [seed]
- 140-irisc-vm — эмулятор прошивки: VM для исполнения образа (FS2/FS3/FS4) на модели внутреннего CPU — отладка правок без живого железа [utopia]
- 150-cx6dx-enib-root — CX-6 Dx: EN→IB + рут на non-secure Dx-карте (офлайн-задел есть) [seed]
- 160-mlxfw-rust — mlxfwutil Rust: финальный инструмент, порт PoC (кол mlx-fw-tui; модуль PoC — mlxfwutil.py) [seed]
- 170-factory-image — factory-образ (mlxfwutil factory): base GUID/MAC + кастомный PSID в образе [seed]
- 180-cx5-secure-dell — secure-фаза: Dell 6120 mixed-CODE на secure CX-5 (41:00.x), FNP-burn [seed]
- 190-serdes-decomp — SerDes-провижининг (shared vs dedicated) + полная декомпиляция секций (корпус+псевдокод); пересмотр негативов Gen4/FDR [seed]

## 050-hardware — железо: инвентарь (ярлыки карт) и SKU
- 100-inventory — локальный инвентарь: ярлыки `CARD_*`, стикеры/чипы дословно; реальные Base GUID/MAC — в `hardware.local.md` (untracked), скрипты — `mlxfwutil.hw()`
- 110-connectx5-sku — CX-5 карта SKU (OPN ↔ спецификация)

## 150-external — внешние инструменты и исходники
- 000-pinned-revs — pinned-ревизии всех `refs/src/*` (сводная), расхождения с историей; вендор-патчи mstflint — provenance сборки
- 100-mstflint/010-walkthrough — mstflint: карта исходников (где что лежит); приложение — сводка расхождений сторонних тулов vs mstflint
- 100-mstflint/020-oss-vs-mft — OSS mstflint vs закрытая MFT: что есть/чего нет, расхождения с локальными образами
- 110-misc-tools/010-cx5-gen4-tool — `cx5_gen4_enable.py` (FS4): разбор и сверка; что брать / что НЕ брать
- 110-misc-tools/020-betep-scripts — BeTeP `fs2_update_ini.py` (FS2/GPH, ini/PSID-логика) и `mfa_extract.py` (MFA-контейнер, не ядро)
- 120-syndicate/010-mlx5fw-mlx5cmd — irisc-syndicate: карты `mlx5fw` (Rust/deku-парсер FS4) и `mlx5cmd` (flash I/O MFPA/MFBA); значение для mlxini

## 250-re — реверс: факты с метками происхождения
- 100-formats/005-detect — детекция формата образа (CheckFwFormat, маги, кандидаты смещений, version word)
- 100-formats/010-fs2 — FS2/GPH (CX-2/3): структура секций, IMG_INFO TLV, эмпирика HP-пакета
- 100-formats/015-fs3 — FS3 (CX-4/CX-4Lx): бут-заголовок, ITOC-заголовок, эмпирика укладок
- 100-formats/020-fs3-sections — FS3: ITOC-запись, типы секций, карта частей, эмпирика образов
- 100-formats/025-crc — CRC-16 (общий FS2/3/4): цикл mstflint Crc16, HW-CRC calc_hw_crc
- 100-formats/030-fs4 — FS4 (CX-5/6): запись/заголовок ITOC, DTOC, специфика, позиция ITOC
- 100-formats/035-fs4-hashes — FS4 hashes table: локация HW-указателя, структура, верификация
- 100-formats/040-fs4-domains — FS4: домены исполнения, внутр. сигнатуры, бут-цепочка, DTOC vendor-cert
- 100-formats/045-fs4-dc-rt — FS4: извлечение MAIN_CODE CX-6Dx, dc↔rt-калибровка
- 100-formats/050-fs4-burn-order — FS4: инвариант burn-order (sector-erase механика, гейты)
- 100-formats/051-fs4-cx7-encrypted — FS4 CX-7 (rev 1.1): контейнер доставки vs A/B-физика флеша, per-burn шифрование, read-политика (secure/FNP), CoRIM-манифест
- 100-formats/055-fs5-pldm — FS5 и PLDM-упаковка (identifiers, pldm_crc32)
- 100-formats/060-chip-map — маппинг чип → PCI device_id → формат → образы refs/fw
- 100-formats/065-fw-trace — FW-трассировка iTrace/mstfwtrace: маска/уровень, классы, ограничения
- 100-formats/067-prs-zlib — PRS и секция 0x30 (DBG_FW_INI): zlib, dc-эквивалентность, флаги образа
- 100-formats/070-transceiver-eeprom — трансиверы: EEPROM-форматы, теорема SFP28, QSFP-оговорка, образы/откаты
- 100-formats/075-phyuc-consts — PHY_UC_CONSTS (0x0B): grid 32+16×176, классы энтропии, generation-invariant таблицы, CX-6-gen нулевой плейсхолдер, H-C-вердикт
- 110-signing/005-mechanism — механизм подписи: mlxsign_lib, digest vs RSA, эмпирика сигнатур (приложение)
- 110-signing/010-payload — payload подписи: что именно подписывается, бит-в-бит SHA-256, V2-маски
- 110-signing/015-key-sections — секции подписей/ключей (ITOC): типы, layout вольтов, IMAGE_INFO-флаги
- 110-signing/020-cli — CLI подписания (mstflint): справочник фактов
- 110-signing/025-secure-boot — Secure Boot VERSION_1/V2: окно, критические секции, диф AE↔AC (приложение)
- 110-signing/030-root-of-trust — root of trust: кремний vs flash, вердикты по платформам
- 110-signing/035-securefw-map — RE-карта MAIN_CODE 16.35.8008: кросс-карта 8008↔4030, secure-биты, md5-приложение
- 110-signing/040-key-resolve — ключ-резолв burn-verify: RSA-ветка, парити-гейт, вердикты H1/H2 (H3 — в 030)
- 110-signing/045-error-branches — ветки ошибок verify: event FW → код MCC
- 110-signing/050-spi-read-policy — SPI-закрытие и read-политика MCDA на secure-fw карте
- 110-signing/055-cx6dx-signing — CX-6 Dx (FW 22.50): RE-якоря, burn-verify, бут-якорь вне flash
- 110-signing/060-nvconfig-securefw — NV-config vs secure_fw: поверхность lifecycle-ключей
- 110-signing/065-secure-fw-bit — secure-fw — бит регистра MGIR (состояние живой карты)
- 120-irisc/005-endian-addressing — iRISC: эндианность (BE слов), dc↔rt base по поколениям, CR↔RAM↔regspace
- 120-irisc/010-isa — iRISC ISA: установленные семантики; аддендумы fuzz-5/isa-max (карта селекторов), errata cc2/lt32
- 120-irisc/015-decoders — iRISC: канонические декодеры; баги/errata декодеров (branch-cc, q-form EA, align-down)
- 120-irisc/020-ghidra-pipeline — Ghidra-пайплайн iRISC (контейнер-компаньон, пины); slaspec provenance
- 120-irisc/025-boot-injection — boot-инъекция iRISC (CX-5): точка/патч 7 слов, host-CR канал VSEC, постулаты
- 120-irisc/030-cx4lx-detour — детур на CX-4 Lx: каркас, геометрия, ISA-паритет, dispatch, read-каналы
- 120-irisc/035-cx4lx-trace — trace-машина 14.32 (CX-4 Lx): iTrace из кода, кадр, db0-строки
- 120-irisc/040-cx4lx-hook — runtime-хук v3 (CX-4 Lx): сайт трассировки в register-хэндлере
- 120-irisc/045-cx4lx-boot-window-cablepath — CX-4 Lx: boot-окно/driverless-трейс + cable-path (QSFP↔SFP)
- 120-irisc/050-cx4lx-dump-cycle — CX-4 Lx: полный dump-цикл (посев → хук → ответ хосту); R-A4b negative
- 130-cable-gate/002-transceiver-ib-gate — FW-гейт скорости IB: цепочка MAIN_CODE, патчи дуги (C12), 2×2-матрица легальных углов
- 130-cable-gate/005-chain — cable-speed gate: цепочка end-to-end (симптом → PDDR → хост)
- 130-cable-gate/010-wall — стена фазы A: полная карта тупиков (чтобы не повторять)
- 130-cable-gate/015-speed-bits — eth_speeds_supported: биты скоростей в FW_MAIN_CFG
- 130-cable-gate/020-implications — стена: следствия для фаз B–D
- 130-cable-gate/025-ch3-results — итоги главы 3 арки «Трансиверы под IB» (гейт снят) и ретест 8008

## 550-poc — заделы сборочного инструмента (PoC)
- 100-mlxfwutil/010-ini-mapping — встроенный ini: секция 0x30 DBG_FW_INI, zlib/PRS-цепочка, маппинг .ini-полей
- 100-mlxfwutil/020-patch-matrix — патч-матрица: секция → что можно менять → зависимые CRC/поля; смешиваемость, flash-пути, офлайн-гейт
- 100-mlxfwutil/030-signing-notes — подпись: выводы для инструмента (mlxfwutil)
- 100-mlxfwutil/040-probes-catalog — каталог пробников `scripts/probes/`

## 750-exp — эксперименты: записи инициатив, разведка, верификация
- 100-dell-base-vpi-build — Dell-база: фаза 1 (merge конфиг-секций, 2 варианта, бут)
- 110-dell-base-rework — переработка Dell-базы (лестница E0–E5 + A/B-расследование)
- 120-eda-ib-node — EDA → IB-узел: результаты фаз
- 130-cx4lx-pcie-gen4 — PCIe Gen4 на CX-4 Lx: отрицательный результат (Gen3-силикон)
- 140-post-fnp-guid-desync — post-FNP quirk: Base GUID/MAC = N/A при целой NVRAM [closed]
- 150-hw-verify-100g56g — железная проверка патча 56G (CX-4, CX-5/HPE)
- 160-hpe-cx5-vpi-gen4-precheck — precheck HPE CX-5 (VPI+Gen4+56/100); роадмап не принят
- 170-securefw-live-gates — live-гейты secure-fw: burn-верификация и boot-гейт (итоги)
- 175-irisc-injection-burns — burn-циклы iRISC-инъекции v1–v5 (итоги: FNP-флоу, MCC-отказ, артефакты)
- 180-serdes-provisioning — SerDes-провижининг (арка C): вердикты shared/dedicated, роль ланов (port-struct), boot-домен, эррата REL24, C5 live-пробы, вход для арки D
- 190-serdes-sku-provisioning — поле-карта провижининга по SKU-диффам: методика same-PSID контролей, шумовые регионы 0x11/0x12, поле-кандидаты

## 850-howto — проверенные рецепты (дистиллят удачных конвертаций)
- 100-cross-flash-ops — кросс-флеш: операционный документ (процедуры)
- 110-transceiver-programming — программирование/перекодировка трансиверов
- 120-field-merge — field-merge: методология сборки кастомной прошивки из частей
- 130-rom-dump — ROM-дамп iRISC (flash / BootPages / shellcode)
- 140-fw-upgrade — апгрейд FW CX-4 (12.28.4706)
- 150-fw-trace — FW-трассировка (mstfwtrace): шаги, маркер-верификация, restore, деградация tracer-core
- 170-signing-practical — подпись образа: практические ответы (3 способа)
- 180-securefw-recipes — secure-fw карта: рецепты (self-signed, FNP-once, чтение, откат)
- 190-irisc-build-burn — сборка и burn iRISC boot-инъекции (CX-5, 4030 CDA): clcrc-пайплайн, шаги + гейты
