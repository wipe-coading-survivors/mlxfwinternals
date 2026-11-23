# 200. Out-of-band I2C (CH347 → ConnectX): рецепт брингапа и дамп-сессии

Дата: 2026-11-21 (брингап), финал 2026-11-22. Статус: **цикл 2 закрыт —
полный live-контур**: электрика → ACK → dev-id → CR-чтения → GW
(RDID/дамп) → W1 write-механика → FNP-дамп 16 MiB, побайтово ==
PCI-`rb` той же карты. **Цикл 3 закрыт 2026-11-22 — продукт-бэкенд
mstflint (§11)**: `q`/`dc`/`rb`/burn-restore через ch34x на live-железе,
включая FNP-приёмку (md5 == T6-дампу, штатный бут после парных burn).
План `docs/superpowers/plans/2026-11-20-mtusb-i2c-hw.md`;
протокольный канон — `docs/250-re/140-oob-i2c/100-protocol.md`;
транспортная спека —
`docs/superpowers/specs/2026-11-19-mtusb-i2c-transport-design.md`.
Журналы: `docs/superpowers/journal/2026-11-2[12]-mtusb-i2c-hw-task-0*.md`
(цикл 2), `docs/superpowers/journal/2026-11-22-mtusb-i2c-impl-task-0*.md`
(цикл 3).

## 1. Цель и охват

Доступ к ConnectX out-of-band (мимо PCI/хоста): внешний I2C-мастер →
CR-space карты → flash-GW — аналог MTUSB-1. Проверено циклом 2 (CX-5
MT27800, root-bazzite; матрица поколений — §8): probe/scan, dev-id,
CR-read (дворды/блоки), GW-циклы RDID/READ, полный дамп flash, запись в
GW DATA-окно без Go (W1), FNP-сессия с PCI-сверкой. Цикл 3 добавил
продукт-бэкенд mstflint (§11): ICMD-обмен (H1 SUCCESS), rb/burn-restore
через ch34x на FNP с PCI-сверкой. **Не покрыто**: burn на
functional-карте (семафор живого FW — только FNP/livefish-окно);
write-limits CH341; 42 Б-кадры (W1-остаток).

## 2. Iron

| компонент | факт |
|---|---|
| Адаптер | **CH347 V1.0** (Zigong Yaojiedianzi, фиолетовая, чип CH347T, USB `1a86:55db` «USB To UART+SPI+I2C», mode #1, bcdDevice 0544; форм-фактор — копия чёрного CH341A). 24xxx-позиция ZIF питается жёстко 5 В (onetransistor-1) — **VCC к карте НЕ подключать** |
| Альтернатива CH341A | PACBTECH CH341A (чёрный, 1a86:5512). До мода — исключён электрически: ZIF13=SDA idle 1.88 В (LED-in-series топология), ZIF14=SCL 5 В. После 3.3V-мода владельца (VCC чипа → 3.3 В): SCL (ZIF14, встроенный pull-up чипа) — чистые 3.2 В; SDA (ZIF13) за LED-цепью — 1.62 В idle / 2.10 В под картой; перепайка не потребовалась. Вердикт цикла 3 (Task 6): **supported (read-path)**, write-limits не проверены; дефолт продукта — CH347T (§11) |
| Хост транспорта | `root-bazzite`; USB-порт, I2C = **interface #2** (class ff, драйвера нет — cdc_acm сидит только на IF0/IF1), **bulk OUT EP 0x06 / IN EP 0x86** |
| Карта-цель | CX-5 MT27800 [15b3:1017], non-secured → slave **0x48**; группа пинов у первого порта SFP+ возле FNP-джампера, подписана SCL/SDA/GND (единственная группа) |
| Транспорт | `scripts/ch347i2c.py` — ctypes/libusb-1.0 (pyusb/pip на bazzite нет); **семья legacy AA** — единственная рабочая на fw 5.44 (mphsi 0xD9/0xDB игнорируется, IN-таймаут) |

Протокол CH347T I2C (рабочая семья; каноны: aystarik/ch347_vcp +
WCH ch34x_mphsi_master_linux): кадр `0xAA` + токены `0x74`=STA
`0x75`=STO `0x80|N`=OUT `0xC0|N`=IN `0x60|spd`=SET `0x00`=END —
идентичны CH341; пресеты 0=20k 1=100k 2=400k 3=750k; **статус-семантика
отличается от CH341**: по статус-байту на каждый OUT-байт, `0x01`=ACK /
`0x00`=NAK (не бит 0x80); чанк wire-транзакции ≤0x3F.

### Распиновка (доказана continuity + рабочим обменом)

- **ZIF13 = нога чипа CH347T 11 = SCL → SCL карты; ZIF14 = нога 12 =
  SDA → SDA карты; ZIF4 = GND → GND карты.**
- 3 провода (~до 20 см), VCC нигде не подключён; обе стороны поднимаются
  вместе (CH347 в USB до power-on хоста).
- Яма новичка: шелк платы CH347 подписей ZIF не имеет; исходная гипотеза
  «ZIF13=SDA/ZIF14=SCL» (в стиле CH341A) была **перевёрнута** — правильная
  полярность доказана омметром владельца (continuity до ног чипа 11/12).
  При «молчании» шины — своп пары 13/14 + рескан (дешёвый дискриминатор).

## 3. Электрика (критерии + факты цикла 2)

| замер | критерий | факт (2026-11-21/22) |
|---|---|---|
| Релька линий ZIF13/14 (плата CH347) | ≈3.3 В (не 5 В!) | 3.2 В idle — OK |
| Карта SDA/SCL idle | ≈3.3 В | 3.2 В — собственные pull-up карты есть → **прямое подключение**, внешние резисторы не нужны (последовательные 2.2–4.7k сломали бы низкий уровень) |
| Первый контакт | 20 кГц (min preset) | исполнено; ACK стабилен @20k/@100k; **400 кГц валидирован** полным дампом (T6-opt) |
| Honesty-гейт | латентность ≥ честного пола клока | @20 кГц: probe ≥0.45 мс (факт 0.65–0.75), mread4 ≥4.5 (4.81), blk16 ≥9.9 (10.21), blk64 ≥31.5 (31.87). Суб-полная латентность = fw адаптера деградировал/фабрикует — данным не верить |

## 4. Команды (воспроизводимые; `scripts/ch347i2c.py`)

```sh
scp scripts/ch347i2c.py root-bazzite:/root/
# 1) скан + стабильность (ожидание CX-5 non-secured: 0x48; +0x1f — сосед, НЕ ТРОГАТЬ)
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 0 scan'
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 0 probe --count 10'
# 2) dev-id + CR-чтения (канон §2.1/§2.3; devid = cr_read32(0xf0014))
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 0 devid'
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 0 crread 0xf0408'   # guard-пара
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 0 crread 0xf0014 64' # блок, автоинкремент
# 3) GW: smoke+RDID / чтение 16Б flash (функциональная карта — только при
#    свободном семафоре; FNP/livefish — всегда с --force-lock, см. §7)
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 1 gwsmoke --force-lock'
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 1 gwread 0x0 --force-lock'
# 4) дамп: канонический (per-block lock) и быстрый (batch+packing, 400 кГц)
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 1 gwdump \
  /root/dump.bin --intra-ms 0 --inter-ms 5 --force-lock --resume --deadline-min 360'
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 2 gwdump \
  /root/dump.bin --opt 2 --batch 64 --inter-ms 0 --force-lock --resume --deadline-min 60'
# 5) W1 write-механика (GW DATA 0xf0410..0xf041f, без Go): только cold-start
ssh root-bazzite 'python3 /root/ch347i2c.py --addr 0x48 --speed 0 w1 --cold --variants 1'
```

Механика длительных операций: `gwdump` — nohup + PID (`$!`), **kill
запрещён** (семафор; 100-cross-flash-ops §1.2) — только внутренний
`--deadline-min`; sidecar `<out>.progress` для `--resume`; wedge-recovery
адаптера (libusb reset + re-claim) + 1 ретрай блока.

## 5. Тайминги (лестница, 16Б-блок = 9 транзакций канона §8.2)

| режим | blk/s | полный дамп 16 MiB |
|---|---|---|
| канон @100 кГц, intra2/inter10 | 26.99 | ~10.8 ч |
| канон @100 кГц, intra0/inter5 | 64.67 | ~4.5 ч (факт: 270.2 мин, 0 ошибок) |
| `--opt 2` (batch+packing) @100 кГц, inter0 | ~500+ | ~35 мин (оценка) |
| **`--opt 2` @400 кГц, inter0** | 705 (замер) / 685.54 (полный) | **25.5 мин** (факт, 0 ошибок) |

Контрольные величины: PCI-`rb` 16 MiB ~3 мин; шкала MTUSB-1 MFT — burn до
45 мин. Целостность: канонический и оптимизированный дампы + PCI-`rb` —
md5 `7b96921b0fdfec100171cb426919cb9d`, байт-в-байт (3 независимых пути).

## 6. Известные ямы (все — факты журналов T1–T6b)

1. **0x1f-подвес (POISON)**. Сосед 0x1f ACK'ает, но за ним нет
   регистрового интерфейса (combined-чтение возвращает ff×16 —
   pull-up уровень); **одно combined-чтение @0x1f переводит ОБА слейва
   (0x48/0x1f) в тихое NAK-состояние** (карта функциональна, линии 3.2 В).
   На CX-5 сопутствовало ICMD-застревание (522 на mstfwreset/mstflint);
   на CX-6 Dx — без 522 (i2c-only). Лечение — **только полный power cycle
   (BMC)**; re-plug адаптера и mstfwreset не помогают. Правило: к 0x1f не
   обращаться. Воспроизведено на двух поколениях (CX-5, CX-6 Dx).
2. **Семафор GW на функциональной карте**. Post-boot окно свободы —
   переменной длины (4–22 мин по двум бутам); захват FW **провоцируется
   первым GW-областным чтением бута** (задержка секунды–минуты, паттерн
   3/3), не временем и не хостовой PCI-активностью. Poll-first-обёртка
   самопораженческая → **канон взятия lock — cold-start** (`w1 --cold`:
   R@0xf0420 базис → 150 мс → W disable → 500 мс → одиночный verify
   CMD@0xf0400 бит31=0; ни одного предварительного CMD-чтения). После
   сессии FW-housekeeping очищает DATA-окно → read-back-гейт валиден
   только немедленно после write.
3. **ZLP-ведж**. ZLP после write-кадра валит fw 5.44 (n=1, кадр 26 Б;
   длинные кадры не тестировались): IN-эндпоинт молчит (rc=-7 на всём
   последующем). Лечение — USBDEVFS_RESET. ZLP не нужен (кадр 26 Б
   доезжает как есть) и гейтен за `--allow-zlp`.
4. **fw-крэш от молотения**. Непрерывные пробы на макс. темпе валят fw
   адаптера (USB-flap, error -71/-110; одиночные сканы выживают). После
   крашей — деградация (суб-полные латентности, «фабрика»-ответы) до
   полного обесточивания. Дефолт `--pause-ms 500`; dumps — мягче
   (`--intra-ms/--inter-ms`).
5. **mute@0x48 на поколениях ≥6**. CX-6 Dx/CX-7: ACK честный, данные
   driven-нули (≠ ff-подтяжке) при живом PCI-CR; реальный файл — у CX-7
    на **0x47** (secured-адрес; см. §8). Оговорка-конфаунд: обе gen≥6-карты
   в выборке secure-fw, non-secure CX-6 не проверялся.
6. **transient-garbage первого чтения**. Первое combined-чтение @0x47
   (CX-7) дало мусор 0xc07fffff, второе — стабильный 0x218 == PCI (живой
   аналог retry-мотивировки mtcr §3 п.5). При смене адреса — перечитать.
7. **dword-квантование CR-записи**. Запись по невыровненному адресу
   ложится вниз на границу dword (0xf0416 → фактически 0xf0414).
   Re-addressed split (W1-5) — только выровненные под-адреса
   0xf0410/0xf0414/0xf0418/0xf041c.
8. **«Фабрика нулей»**. Read-кадр на NAK-ающей шине завершается за ~0.8
   мс и возвращает 64×0x00 — fw адаптера симулирует. Гейт: проверка
   статус-байт на каждом чанке + латентностный пол (§3).

## 7. FNP-сессия (гарантированный GW-путь: стряп → дамп → PCI-сверка)

FW не работает → guard-путь свободен, семафор держит HW/recovery-agent
(обе стороны — i2c и PCI — видят одно и то же). Последовательность (T6,
всё исполнено 2026-11-22):

1. **Стряп** (руки владельца, по 100-cross-flash-ops §9.1/§15): poweroff →
   джампер FNP → power on. Документированной позиции джампера для
   ADA/ACA нет — разведка владельцем. Контроль: `lspci -nnd 15b3:` →
   **`[15b3:020d]` Flash Recovery** (сетевой функции нет — норма).
2. **Брингап**: `probe --count 3` → ACK; `devid` → 0x020d (rev-биты в
   livefish дают 0x0 против A0 в NORMAL — факт); guard: 0xf0408=0,
   0xf040c≠0 — норма (recovery-agent держит cache-rep; аналог -ocr).
3. **Force-lock**: семафор занят HW → `--force-lock` (release stale
   W CMD=0 — T15-прецедент «taking flash lock even though semaphore is
   set») — освобождает персистентно ОБЕ стороны (после i2c-очистки
   PCI-`rb` проходит).
4. **RDID**: `gwsmoke --force-lock` → jedec `ef 40 18 00` = Winbond,
   16 MiB (объём дампа — по cap-биту); ADDR-smoke W→R 0x0 — двусторонний
   CR-write-smoke.
5. **Дамп**: `gwdump` (§4 п.4) — nohup+PID, `--resume`, self-stop;
   критерий DONE: процесс вышел + лог DONE + размер == объёму + md5.
6. **PCI-rb кроссчек** (строго ПОСЛЕ i2c-дампа — не конкурировать за
   семафор): `mstflint -d <BDF-020d> rb 0x0 0x1000000 /root/pci.raw`;
   md5 обоих + `cmp` — байт-в-байт.
7. **Структура** (mlxfwutil.py / xxd): CX-5: голова @0x0 = MTFW-магия
   (не dead9270!); слот A — валидный FS4 (psid/ver читаются, ITOC
   @0x5000); слот B @0x800000 — сигнатура zeroed (инвалидирована);
   DTOC @0xfff000, MFG_INFO @0xff8000, DEV_INFO @0xfd0000; хвост
   0xfa0000+ — all-FF.
8. **Tearing-down** (владелец): poweroff → снять джампер → power on →
   verify `1017`/`q`/`dc`.

## 8. Матрица поколений (live, T6b; все карты functional)

| карта | hw_id (PCI CR) | секьюрити | ACK-адреса | данные @0x48 | данные @0x47 |
|---|---|---|---|---|---|
| CX-5 ACA [15b3:1017] | 0x020d | non-secured | 0x48, 0x1f | **живые** (полный CR, GW-путь) | — (NAK) |
| CX-5 Ex Dell [15b3:1019] | 0x020d | secure-fw | только 0x48 | **живые** | — (NAK) |
| CX-6 Dx [15b3:101d] | 0x0212 | secure-fw | 0x48, 0x1f | mute-нули | — (NAK) |
| CX-7 FB_ [15b3:1021] | 0x0218 | GA SECURED | 0x47, 0x48, 0x1f | mute-нули | **живые** (gen6-guard 0xf0484/0xf0488) |

Правило: 0x47-активность следует за поколением/hw_id (∈ secured-таблицы
mtcr), не за секьюрити-стейтом карты. Guard-пара 0xf0408/0xf040c —
legacy/gen5; для CX-7 живая пара 0xf0484/0xf0488. На CX-7 — строго
read-only (GA SECURED, прецедент 100-cross-flash-ops §17).

## 9. Приёмка цикла 2 (спека §8 — построчно)

1. **ACK @0x48** — ✅ T1: 20/100 кГц, стабильность 10/10 (+ матрица §8:
   0x47 у CX-7 live).
2. **dev-id, совпадение с поколением** — ✅ T2: 0x020d == lspci-классу
   [15b3:1017] (ConnectX-5, rev A0); T6b: 0x212/0x218 == PCI-CR.
3. **CR read/write (двусторонний smoke)** — ✅ с оговоркой. Read: T2
   (дворды/блоки 16/64 Б, автоинкремент). Write: плановый T3-шлюз
   (ADDR-smoke на функциональной карте) **не исполнен — семафор у живого
   FW**; эквивалент доставлен T5 r3 (W1 v1: write 16Б в GW DATA +
   побайтовый read-back под cold-lock) и T6 (ADDR-smoke W→R + v5
   mwrite4×3 + read-back, FNP).
4. **RDID через GW (guard учтён)** — ✅ T6: jedec Winbond 16 MiB;
   FNP-guard 0xf040c≠0 — норма recovery-agent (reset-write не потребовался).
5. **Дамп + сверка с PCI** — ✅ T6: 16 MiB, 0 ошибок, md5
   7b96921b0fdfec100171cb426919cb9d, PCI-`rb` байт-в-байт (плюс
   повторный дамп другим режимом — 3-way). Functional-путь (T4) отменён —
   семафор; дамп доставлен FNP-путём.
6. **Тайминги → экстраполяция; W1 решён** — ✅ §5 (26.99→685.5 blk/s);
   W1 v1 DELIVERED (26 Б как есть), ZLP вреден, v5 — с выравниванием.
7. **[live]-пункты O4/O5/O9/O10 закрыты или сужены** — ✅ см. спеку §9
   (O4 closed, O5-факт, O9 closed, O10 read+write closed; O7 refuted).

## 10. Ссылки

- План: `docs/superpowers/plans/2026-11-20-mtusb-i2c-hw.md`
- Канон протокола: `docs/250-re/140-oob-i2c/100-protocol.md`
- Спека транспорта: `docs/superpowers/specs/2026-11-19-mtusb-i2c-transport-design.md`
- FNP-механика/burn-флаги: `docs/850-howto/100-cross-flash-ops.md` (§1.2, §6, §9.1, §15)
- Журналы: `docs/superpowers/journal/2026-11-2[12]-mtusb-i2c-hw-task-0*.md`
- Канон CH347 (исходники): aystarik/ch347_vcp; WCHSoftGroup/
  ch34x_mphsi_master_linux; плата: onetransistor.eu 2024/09 + 2024/11

## 11. Продукт: нативный ch34x-бэкенд mstflint (цикл 3, mtusb-i2c-impl)

Живые факты цикла 3 (журналы `2026-11-22-mtusb-i2c-impl-task-0*.md`);
реализация — патч 1.5 к mstflint 4.37.0 (сиблинг
`../mstflint-container`); O-статусы цикла — спека транспорта §9.

### Деплой / AppImage

- `make mstflint-deploy HOST=<alias>` из sibling-репо: AppImage
  `mstflint-4.37.0-1.5-x86_64` + симлинки из manifest (`mstflint`,
  `ch34x_frames`, …); `libusb-1.0.so.0` вендорится в образ. Запуск по
  симлинку live-проверен на root-bazzite (FUSE-маунт AppImage); в
  окружениях без FUSE/для офлайн-проверки — распаковка
  `./mstflint --appimage-extract` (так извлекался `bin/ch34x_frames`
  для golden-тестов цикла 3).

### Device-name и листинг адаптера

- `-d ch34x:<bus>.<addr>` (hex-грамматика) или короткое `ch34x` —
  резолвится при ровно одном адаптере в USB.
- Листинг: `-d ch34x:9.9 q` → `adapter not found` + список
  `ch34x:<bus>.<addr> (<профиль>)` всех найденных + rc=1; профиль
  печатается per-PID (55db→ch347, 5512/5523→ch341) — это и чек
  идентичности адаптера (`lsusb` на хосте нет).
- **PIT (цикл 3)**: идентичность адаптера проверять по USB PID **до**
  обвязки/трафика — ожидался CH347T (55db), фактически была воткнута
  5512 (CH341A). При смене адаптера ZIF-маппинги зеркальны (§2):
  CH341A ZIF13=SDA/ZIF14=SCL; CH347 ZIF13=SCL/ZIF14=SDA.

### Env-ручки (все опциональны; мусор → warning + default)

| переменная | смысл | default |
|---|---|---|
| `MLXCH34X_SPEED` | пресет шины 0=20k, 1=100k, 2=400k, 3=750k (кГц) | 2 (400k) |
| `MLXCH34X_PAUSE_MS` | межтранзакционная пауза, мс (троттлинг против fw-краша адаптера при плотном молотении — §6 п.4) | 0 |
| `MLXCH34X_TRACE=frames` | построчный дамп кадров (`ch34x OUT[n]: …` / `IN[n]: …`) в вывод команды | off |
| `MLXCH34X_FORCE_LOCK=1` | на open (после set-speed, ДО пробы sec-addr и любого mflash-lock) один mwrite4 CMD@0xf0400=0 @slave 0x48 — stale-release семафора (T15-прецедент); неудача кадра — warning, open продолжается | off |

- **FORCE_LOCK — только FNP/livefish**: на функциональной карте затирает
  легитимно удерживаемый живым FW семафор (FW держит bit31 персистентно,
  §6 п.2). На FNP освобождает персистентно обе стороны (i2c + PCI).
- **TRACE=frames — предупреждающий размер**: один i2c-burn 16 MiB даёт
  ~356 МБ трейса; даже одиночный `q` на FNP — 433K OUT-строк. Включать
  осознанно, длинные операции пускать с redirect в файл.

### Скорости (live-факты; blk = 64 Б для ICMD-пути, 16 Б для GW)

Functional-карта, ICMD-MCC путь чтения (`rb 1 MiB`, `PAUSE_MS=0`):

| MLXCH34X_SPEED | кГц | wall, с | blk/s | KiB/s | мс/блок |
|---|---|---|---|---|---|
| 0 | 20 | 1339 | 12.24 | 0.765 | 81.7 |
| 1 | 100 | 283 | 57.85 | 3.62 | 17.3 |
| 2 | 400 | 82 | 200.03 | 12.50 | 5.0 |

md5 всех трёх окон совпали (3-way; скорость не портит данные).
ICMD-rb при дефолтном pacing — **клок-баунд, не delay-баунд** (20→100
кГц ускорение 4.7× при идеале 5×, 100→400 кГц 3.5× при идеале 4× —
эффективность 95%/86%): тезис спеки §5.5 «межпакетные задержки
доминируют» верен только для GW-batch-пути harness (§5, насыщение
1.37×); при 400 кГц overhead USB-кадров ≈2/3 времени блока — дальше
ускорять batching/packing'ом, не клоком.

FNP, GW-путь продукта (per-op lock, 7 tx/16Б-блок):

- полный `rb` 16 MiB через ch34x: **49.8 мин** (352 blk/s, ~2465 tx/s
  @400 кГц); md5 == T6-дампу и PCI-`rb`.
- burn/restore 16 MiB (legacy-набор `-ocr -apc --nofs
  --ignore_dev_data -y`): через ch34x **22 м 46 с**; PCI-базлайн того
  же образа — 1 м 58 с; оба verify md5 == T6, после — штатный бут,
  GUID/MAC живы.
- `q` на FNP через ch34x — небыстрая операция (~43 tx/КБ, 433K
  транзакций): **band ≥300 с**.

Не проверено живьём: fallback скорости после wedge-recovery
(восстановление ни разу не срабатывало за весь цикл — сессии 23–50 мин
на 400 кГц прошли без единого wedge/NAK-шторма).

### Live-дисциплина (уроки инцидентов n=2, цикл 3 Task 6)

- **Не пайпить live-вывод mstflint** (`tee | head` → SIGPIPE =
  mid-ICMD kill → flash-semaphore wedge); SIGTERM таймаут-банды внутри
  ICMD write-burst — тот же эффект. Только redirect `> file 2>&1`,
  чтение файла отдельной командой.
- **Band таймаута > ожидаемой длительности** операции (q на FNP ≥300 с;
  см. скорости выше); иначе — ложный rc=124 при живой карте.
- Длинные операции — `nohup` + PID (`$!`) + поллинг/дедлайн; kill
  mid-burst запрещён.
- **Hang карты** (PCI `q` wedge/timeout) → немедленный BMC power cycle
  (ipmi-ops), ноль ретраев против молчащей карты. При semaphore-wedge
  (kill mid-ICMD, n=2) лечено только BMC cold cycle; re-plug адаптера /
  clear_semaphore не пробовались (приказ — сразу cold cycle) —
  T15-прецедент split (100-cross-flash-ops: clear_semaphore не снял
  wedge; журнал 2026-09-17-cx6dx — снимал), не рассчитывать на них.

### Tier-1 (functional, H1) — закрыт

`mstflint -d ch34x q` на functional CX-5 (Task 5): rc=0, полный вывод,
GUID/PSID == PCI-`q`; кадры трейса байт-в-байт golden; `dc` — 3 с @400
кГц (mlxini-маркер на месте). Гвард NAK@0x48 (тихая шина при плохой
посадке проводов) — латентностный пол harness-пробой отличает «шину
молчит» от «адаптер фабрикует» (§3).

