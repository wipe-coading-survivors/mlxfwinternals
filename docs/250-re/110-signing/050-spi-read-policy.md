# 050. SPI-закрытие и read-политика MCDA на secure-fw карте

> Источник: цикл securefw-gates (2026-10-29, задачи «б»/«в»: task-04 SPI-locus,
> task-05 read-политика) + цикл securefw-read (2026-10-29, task-02/04/05/06 —
> чтение патченым тулингом); журналы
> `docs/superpowers/journal/2026-10-29-securefw-gates-task-{04,05}.md`,
> `docs/superpowers/journal/2026-10-29-securefw-read-task-{04,05,06}.md`
> (адресация — `035-securefw-map.md` §1-2). Live-карта — `CARD_HPE_CX516A`.
> Связи: secure-биты (bit15/bit14 как условие фильтра) → `035` §3;
> рег-фильтр CX-6Dx (RBAC-эволюция) → `055-cx6dx-signing.md` §4; рецепты
> чтения → `850-howto/180-securefw-recipes.md`; пин патч-тулинга →
> `150-external/000-pinned-revs.md`.

## 1. SPI-закрытие: два слоя

1. **ROM/аппаратный cr-space protection по IMAGE_INFO bit15**: образ-код
   окно HCR flash-gateway CR 0x2000-0x2020 (GW_CMD/ADDR/DATA, imm 0x800-0x808)
   не пишет (615 ld.i-чтений / 0 st.i-записей по всем кодовым секциям);
   «0xFF-глухота» = шлюз не исполняет host-команды → RDID 0xFF/0x00 →
   `MFE_NO_FLASH_DETECTED` (`mflash.c:665-672`). Не MLOCK, не write-protect.
2. **Рег-фильтр 0x1064c8** (роутер команд 0xc6dd4): при secure_fw
   raw-flash-регистры MFPA(0x9010)/MFBA(0x9011)/MFBE(0x9012) — на спец-ветке
   (подусловие signed_fw 0x1064fc); MCC/MCDA/MCQS/MCQI (0x9060-0x9063)
   проходят всегда ⇒ FW-mediated MCDA — единственный легальный флеш-интерфейс
   живой secure-карты, и он всегда за VERIFY (`035` §3).

Командный блок CR 0x23f4/0x23fc обслуживает isr_icmd 0x107ed8 (рег-акцесс
«check_and_exec_access_register» 0xc7bcc, диапазон 0x9020-0x9064).

## 2. Read-политика MCDA: плоская офсетная

Хендлер MCDA **0x122b90**; условия:

- mcc_en (0x122554) ∧ size≠0 (0x122c34) ∧ size ≤ max_xfer[класс]
  (0x122c48; таблица **0x1d37b0**: класс 2 → MCDA 0x1c, MCQI 0x14; класс 4 →
  0x80; класс 5 → 0x100; иначе 0. BOOT_IMG = класс 4 → **128B** = data[32]
  регистра; классы — таблица dc 0x38b990);
- offset+size ≤ экстент (0x122c60; в активной сессии экстент =
  RAM[0xca8c] = размер образа, резолвер 0x1d0604; фактическая граница =
  конец последней секции ITOC).

Движок: 0x1d5b78 → read_data_from_partition **0x1a424** (range-гейт
partition) → сырой flash-read 0x19208. **Секционного allow-list НЕТ,
маскирования НЕТ, secure-биты не участвуют**; ITOC не консультируется.
rd_en — только MCQI-cap (билдер 0x1d382c, bit31 dword4 @0x1d39f8),
потребляется клиентом, FW-side MCDA его не проверяет.

Эмпирика: P1-P9 (вендорский вольт) и W3-1..9 (наш вольт) — 9/9
байт-идентичное воспроизведение; rb/verify читают весь компонент БЕЗ фильтра
и маскировки сиг-зон. `dc`/`ri` отказывают клиенты ДО FW
(`fsctrl_ops.cpp:1079-1085` / `:547-553` — «Unsupported operation under
Secure FW» / «Read image is not supported», дословно на обеих FW):
наблюдаемые запреты чтения — **клиентские**, не FW.

## 3. Чтение патченым тулингом (mstflint 4.37.0-1.2) — дистиллят

Stock-тулингом ri/dc на secure-карте НЕ читаются (клиентские гварды, §2), но
патченым 4.37.0-1.2 — читаются: dc/ri работают как на non-secure — ri через
`ReadMccComponent(COMPID_BOOT_IMG)`, dc через `imageOps→FwGetSection`
(FW-mediated MCDA); rb/verify работали и до патча. Write-гварды и burn-путь
патчем НЕ тронуты. Состав патчей и пин — `150-external/000-pinned-revs.md`;
пошаговый рецепт — `850-howto/180-securefw-recipes.md`.

- **stderr-маркеры патченного read-пути**: `-W- mlxini secure-read: section
  read served via MCC (Secure FW)` (dc) / `…image read served via MCC
  (Secure FW)` (ri) + `-I- full image read via MCC may take minutes`.
- **Тайминги — минуты-класс**: полный образ ~5 MiB подаётся порциями ≤128B
  (max_xfer класс 4, §2); live ri/dc на 41:00.0 — минуты-класс (внутри окна
  600 с; таймаут операции ≥10 мин); молчаливое ожидание — норма.
- **ri-семантика**: дамп = полный MCC-компонент BOOT_IMG = логический образ
  (0x50e6f0 на 41:00.0), НЕ весь 16 MiB флеша, как direct-path ri.
- **bdc**: оживает автоматически (тот же `FwReadData`-путь); вердикт
  сравнения при size-mismatch (device-буфер ~image vs `FwExtract4MBImage`
  из файла) НЕ гарантирован — live-сверка отдельно, не гейт.
- **Live-доказательства** (цикл securefw-read): ri-дамп == running image
  байт-в-байт по всему диапазону 0x50e6f0, ITOC 0 bad entries (task-04);
  round-trip plain burn дампа PASS, карта в исходном состоянии (task-05);
  регрессия non-secure 01:00.0 — q-diff пуст, dc/ri md5 == baseline
  сток-тулинга (task-06).

## Постулаты / открытое

- [постулат] Полярность block/pass рег-фильтра (arg2 секвенсера 0x106490).
- [постулат] Гипотеза «чтение требует активного handle»: поведение
  patch_gate 0x1cfe6c(0) в idle не декодировано; клиент всегда LOCKается.
- [постулат] Формула pred(r21) → rd_en (MCQI-cap-билдер).
