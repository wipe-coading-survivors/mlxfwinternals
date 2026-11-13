# 190. Сборка и burn iRISC boot-инъекции (CX-5, 4030 CDA)

> Источник: пайплайн сборки — журнал
> `docs/superpowers/journal/2026-09-20-irisc-4030-qft-handler-re.md`
> (§23/§26/§28), скрипт `scripts/irisc/build_4030_patch.py` (golden:
> `tests/test_irisc_asm.py`); burn — журнал
> `docs/superpowers/journal/2026-09-21-irisc-fnp-burn-verify.md`.
> Механика (точка инъекции, патч, канал результата) —
> `docs/250-re/120-irisc/025-boot-injection.md`; итоги burn-циклов v1–v5 —
> `docs/750-exp/175-irisc-injection-burns.md`.
> Связи: ассемблер/clcrc-API/профили — `scripts/irisc/README.md` (скилл
> `irisc-asm`); FNP/кросс-флеш — `100-cross-flash-ops.md`; burn-order —
> `docs/250-re/100-formats/050-fs4-burn-order.md`.

Рецепт воспроизводит v3/v5: детур @ dc 0x1d594 → шеллкод @ dc 0x38d730 →
маркер `0xbadc0001` в CR 0x23f0. Всё живое — только на жертвенной non-secure
карте (здесь `CARD_CX5_EDR100`, 81:00.0); patched/unsigned — только FNP
(hard-rule `100-cross-flash-ops.md` §0).

## 1. Подготовка

1. База — STOCK CDA-4030 (см. приложение `750-exp/175`; проверить md5
   перед сборкой — `a8c60c90473078288b01009c7cad471b`).
2. Ассемблировать/патчить слова — только каноном: `scripts/irisc`
   (`clcrc_unwrap`/`clcrc_wrap`, `irisc_asm` с профилем `cx5`,
   strict + decode-verify каждого слова). Развёртывание 68B-фрейминга
   руками не писать; адресные конвенции — не выводить самому
   (`250-re/120-irisc/005-endian-addressing.md`).
3. Эталонный пайплайн целиком — `scripts/irisc/build_4030_patch.py`
   (шаги 2–7 ниже + все гейты; md5-контроль промежуточных артефактов).

## 2. Сборка (шаги + гейты)

1. Извлечь raw MAIN_CODE (с line-CRC):
   `python3 mlxfwutil.py extract -s 0x03 --raw -o raw.bin <img>`.
   Гейт: ITOC entry 0x03 = size 0x3d15a0, clcrc=1, addr 0x1c748,
   param0 0x800000, param1 0x81d58c.
2. de-clcrc: `mlxfwutil.clcrc_unwrap(raw)` → code+tail (строка = 64B код +
   2B ноль-пад + 2B LE u16 clcrc).
   Гейт: len(code) == 0x397dc0 (для 4030).
3. **ROUND-TRIP-гейт (до патча):** `mlxfwutil.clcrc_wrap(code, tail) == raw`
   байт-в-байт. FAIL → STOP (метод де-clcrc неверен).
4. Патч 7 слов (таблица — `250-re/120-irisc/025` §3). Pre-patch assert'ы:
   orig-слова на местах (0x1d594 = `0x940002de`; 0x1d598 = `0x95000000`
   не трогаем), free-регион 0x38d730..0x38dbe9 all-zero, не цель
   jump/call.
5. re-clcrc: `mlxfwutil.clcrc_wrap(code, tail)`.
   Гейт (v3): меняются ровно 3 68B-линии — 1878 (инъекция), 58204/58205
   (слова шеллкода); прочие 58868 byte-identical.
6. Пересчёт CRC ITOC: `mlxfwutil.patch_sections` — section CRC (crc16_mlx) +
   entry CRC (mstflint-authoritative) в ITOC entry 0x03.
7. `python3 mlxfwutil.py verify --deep <patched>.bin` → **PASS** (ITOC 25 +
   DTOC 7, all CRC OK). Примечание: HASHES-таблицы в этом образе нет
   (`HashesTable.from_image` → None) → hash-проверка deep-verify
   пропускается; SIG-секции криптографически mlxfwutil не проверяются.

Финальная верификация перезатягивает всё из финального .bin (не из
intermediates): round-trip PASS; 7 слов EXACT; word-diff vs STOCK MAIN_CODE
= ровно 7 слов (dc 0x1d594 + 6 слов 0x38d730..0x38d744); dc 0x1d598 не
тронут.

## 3. Модификация .ini (GUID/MAC, коммент) — только без relocation

1. Base GUID/MAC — в DTOC (0xE1/0xE0); идентификаторы карт — реестр-ярлыки
   `CARD_*` (`docs/050-hardware/100-inventory.md`), не hex в командах.
2. **Гейт: packed-размер секции 0x30 ≤ original** (v5: 0x908 ≤ 0x928).
   Рост сверх `e.size` → молчаливый relocation → corruption при burn
   (урок v4 — `750-exp/175` §4).
3. Гейты mlxfwutil (цикл repack-burn-safety): молчаливых релокаций нет —
   `verify` FAIL (burn-order) + предзаписной отказ inject/repack rc 2
   (`--unsafe-relocation` — только research; safe-relocation —
   планировщиком; автознак 0xA0, `--no-autosign` — research) —
   `docs/250-re/100-formats/050-fs4-burn-order.md` §3.

## 4. Burn (FNP)

1. Полная FNP-процедура (strap, write-protect, мониторинг, «не убивать
   mid-op») — `100-cross-flash-ops.md` §9.1; mstflint ≥ 4.34.0.
2. Команда:
   `mstflint -d <BDF> -i <patched>.bin -ocr --nofs --ignore_dev_data -y burn`
   (non-FNP failsafe отклоняется MCC digest-чеком — `750-exp/175` §2).
3. Гейты вывода: **оба** маркера — `Burning FW image without signatures -
   OK` + `Restoring signature - OK`; затем в FNP: `q` (FS4/FW/PSID) +
   `dc` (clean).
4. Снять strap (окно обесточивания) → нормальный boot.

## 5. Post-boot проверки

1. Маркер (VSEC-чтение, `250-re/120-irisc/025` §4.1):
   `setpci`-последовательность CTRL=0x20000002 → ADDR=0x23f0 → poll
   READY → DATA == `0xbadc0001`.
2. Карта healthy: lspci (`15b3:1019`), `mstflint q` (FW/PSID), порт UP,
   dmesg без assert/recover.
3. Base GUID/MAC: при `--ignore_dev_data` — восстановить
   `mstflint -d <BDF> -ocr --guid ⟨реестр CARD_*_GUID⟩ --mac ⟨реестр CARD_*_MAC⟩ sg`
   (MAC без двоеточий); если GUID/MAC зашиты в DTOC образа (v5) — `q`
   показывает их, `sg` не нужен.
4. Целостность (опционально): post-boot `ri` → image-region 0x0..0x55765F
   0 diff vs patched .bin (`750-exp/175` §3).
