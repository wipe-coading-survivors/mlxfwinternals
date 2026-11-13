# 175. Burn-циклы iRISC-инъекции v1–v5 (итоги)

> Источник: live-циклы на `CARD_CX5_EDR100` (81:00.0, ConnectX-5 Ex,
> non-secure, жертвенная) 2026-09-20/21 — журналы
> `docs/superpowers/journal/2026-09-20-irisc-4030-qft-handler-re.md`,
> `docs/superpowers/journal/2026-09-21-irisc-fnp-burn-verify.md`
> (§7–§16); уточнение механики relocation (2026-10-31) — журналы
> `docs/superpowers/journal/2026-10-31-repack-relocation-recon.md`,
> `docs/superpowers/journal/2026-10-31-repack-burn-safety-task-06.md`.
> Здесь — сжатые итоги; механика инъекции —
> `docs/250-re/120-irisc/025-boot-injection.md`; рецепт —
> `docs/850-howto/190-irisc-build-burn.md`.
> Связи: burn-order инвариант и гейты mlxfwutil →
> `docs/250-re/100-formats/050-fs4-burn-order.md`; MCC-коды/ветки →
> `docs/250-re/110-signing/045-error-branches.md`; FNP-полевая процедура →
> `docs/850-howto/100-cross-flash-ops.md` (§6, §9.1).

## 1. Burn-флоу FNP (проверенный путь)

Команда (журнал 2026-09-21 §9, §11):

```
mstflint -d 81:00.0 -i <patched>.bin -ocr --nofs --ignore_dev_data -y burn
```

- **FNP** = hardware-strap (пин): карта показывает `15b3:020d`
  [ConnectX-5 Flash Recovery], class [0580]; strap переживает warm-reboot,
  снимается только физически в окне обесточивания
  (`docs/850-howto/100-cross-flash-ops.md` §9.1).
- mstflint **4.36.0** (Git SHA `f3a3dab`); для FNP-burn обязателен 4.34.0+
  (4.32.0 падал до `Restoring signature` — 100-cross-flash-ops §6).
- Burn в фоне + мониторинг, **никогда не убивать mid-op** (залипает
  flash-семафор → только reboot хоста; 100-cross-flash-ops §0/§9.1). ~2–3 мин.
- **Оба маркера обязаны присутствовать** (100-cross-flash-ops §6):
  `Burning FW image without signatures - OK` + **`Restoring signature - OK`**
  (флэш финализирован). В FNP до burn — снять write-protect
  (`flint_oem -d <dev> -ocr hw query` / `hw set Flash0.WriteProtected=Disabled`,
  идемпотентно); verify в FNP: `q` (FS4/FW/PSID) + `dc` (clean) (журнал
  2026-09-21 §9.1/§9.3, §11.1/§11.3).
- **Чтение CR 0x23f0 возможно ТОЛЬКО после снятия strap + нормального
  boot**: в FNP нет VSEC (минимальный PCIe-config) и iRISC гонит
  recovery-код, не полный MAIN_CODE → шеллкод в FNP не исполняется (журнал
  2026-09-21 §7.2).
- `--ignore_dev_data` → Base GUID/MAC на флэше **N/A** (device-data взяты
  из изображения) → после boot восстанавливать явно:
  `mstflint -d <dev> -ocr --guid ⟨реестр CARD_CX5_EDR100_GUID⟩ --mac ⟨реестр CARD_CX5_EDR100_MAC⟩ sg`
  (MAC без двоеточий; журнал 2026-09-21 §9.3, 100-cross-flash-ops §9.1
  step 4). В v5 (GUID/MAC в DTOC образа) `sg` не понадобился.

## 2. Почему non-FNP burn не проходит (MCC)

Non-FNP burn по умолчанию = **failsafe-flow** (`burnFailsafe = !nofs`,
`flint/subcommands.cpp:2624`): device-side component manager (MCC)
верифицирует **сигнатуру** скачанного компонента **на устройстве**.
Patch-образ несёт оригинальные секции CDA-4030 (SIG_256/SIG_512) →
7-байтный патч ломает digest → MCC отклоняет:
`FWCOMPS_MCC_ERR_REJECTED_DIGEST_ERR` →
«Burning FS4 image failed: The Digest in the signature is wrong»
(`fw_comps_mgr/fw_comps_mgr.cpp:2124-2125`; журнал 2026-09-21 §8.3–8.4).

- **«Correct CRC + non-secure» НЕ помогает**: MCC-чек — про **сигнатуру**
  (digest компонентов), а «non-secure» — enforcement на **boot**,
  независимый от burn-time MCC-чека.
- `--nofs` (`burnFailsafe=false`) → legacy flow (прямой flash-доступ,
  `_mccSupported=false`) → MCC-чек **обходится**. Технически non-FNP burn
  с `--nofs` обошёл бы MCC, но по hard-rule (unsigned/patched — только
  FNP; 100-cross-flash-ops) не выполнялся; **все успешные burn этого
  цикла — FNP + `--nofs`** (v1/v2/v3/v5; v4 — маркеры OK, in-FNP verify
  FAILED, §4).

## 3. Целостность после burn (закрытие цепочки)

Post-boot `ri` → image-region `0x0..0x55765F`: **0 diff vs patched .bin**
→ зашитый код (детур + st.d-цель + CRC) на флэше, и это то, что
забутинилось. Цепочка: md5 файла → FNP-burn 100% + `Restoring signature -
OK` → flash image-region = patched (0 diff) → boot с флэша (lspci, `q`,
порты OK) → **running FW = patched, доверенный** (журнал 2026-09-21 §10.4).
(Tail-файл при live-`ri` — артефакт: видимый через running FW image
~5.5 MiB, erased-области читаются как 0x00 — журнал §8.6.)

## 4. Итоги v1–v5 (что пошло не так + финал)

| # | образ | инъекция | цель marker'а | burn | CR 0x23f0 после boot | итог |
|---|---|---|---|---|---|---|
| v1 | `4030-cda-patched.bin` | dc 0x1d598 (dead code) | **неверный адрес**: RAM 0x223f0 (unmapped-слот) — «0x20000 base» баг: `set2 r3,zero,0x0002`+`set3` → r3 = 0x000223f0, а не 0x23f0 (журнал 2026-09-20 §25.2) | FNP+`--nofs` | 0x0 (маркера нет) | запись в unmapped-слот = no-op **+** инъекция в dead code |
| v2 | `4030-cda-patched2.bin` | dc 0x1d598 (dead code) | **верный адрес**: RAM 0x23f0 (1-словный фикс word0 `0x24030002`→`0x24030000`) | non-FNP отклонён MCC (§2); FNP+`--nofs` | 0x0 (маркера нет) | инъекция в dead code — **шеллкод никогда не исполнялся** (H1, журнал 2026-09-21 §10.6) |
| v3 | `4030-cda-patched3.bin` | **dc 0x1d594** (живая boot-точка, `call 0x1e10c` → `call 0x38d730`) | верный адрес: RAM 0x23f0 | FNP+`--nofs` | **0xbadc0001** (3× стабильно) | **SUCCESS** (журнал 2026-09-21 §12): исполнение подтверждено |
| v4 | `4030-cda-patched4.bin` | инжект v3, не тронут | RAM 0x23f0, не тронут | FNP+`--nofs`: маркеры OK, **но in-FNP verify FAILED** (INI=0xFF @0x557660 + ROM wrong-CRC) | — (не бутался) | **CORRUPTION**: рост .ini 0x928→0x9e8 → молчаливый relocation 0x30 @0x557660 → sector-revisit стёр записанную INI + хвост ROM_CODE (механика уточнена/доказана 2026-10-31 — ниже) |
| v5 | `4030-cda-patched5.bin` | инжект v3, не тронут | RAM 0x23f0, не тронут | FNP+`--nofs`: **все секции OK** (INI @0x4fe000, без relocation) | **0xbadc0001** (3×) | **ФИНАЛЬНЫЙ SUCCESS** (журнал 2026-09-21 §16): инжект + маркер + base GUID/MAC (из DTOC) + коммент в .ini |

Уроки (факт-строками; полный нарратив — git-история исходного дока
цикла restructure-irisc и журналы):

- v1/v2: dead-code точка (0x1d598) + unmapped-слот — механика в
  `025-boot-injection.md` §2/§4.4; v2 попутно доказал MCC-отказ non-FNP (§2).
- v4 corruption (уточнение 2026-10-31, цикл repack-burn-safety): если
  packed-размер секции 0x30 (DBG_FW_INI) вырастает за `e.size`, `inject_ini`
  (mlxfwutil.py) молча релоцирует её в tail-gap + стирает старое место →
  при FNP-burn **INI положена и стёрта**: write-поток (в порядке
  ITOC-записей) возвращается в сектор 0x550000 более поздней записью 0xeb —
  erase сектора без RMW уничтожает только что записанную INI (`0xFF×0x9e8`,
  CRC 0xbd51); «ROM wrong-CRC» = CRC секции **ROM_CODE** (хвост ROM в
  секторе 0x4f0000 стёрт возвратом записи 0x32; CRC 0x408a) — не «сломанные
  подписи» и не «mflash не положил INI» — sector-erase-механика инварианта
  burn-order (`docs/250-re/100-formats/050-fs4-burn-order.md`);
  предсказано и сверено побайтово (журнал
  `2026-10-31-repack-relocation-recon.md` §3.3–3.4; модель подтверждена
  live-L2 — `…repack-burn-safety-task-06.md`).
- **Два независимых триггера роста v4:** (a) коммент в .ini; (b) 4-байтный
  zlib-drift (локальный `zlib-ng 1.3.1` сжимает text на 4 B больше, чем
  zlib сборщика образа — даже no-op re-inject релоцирует).
- **Фикс (v5):** держать packed-размер .ini ≤ original (выкинуть
  эквивалентные байты других .ini-комментов) → секция на месте @0x4fe000 →
  burn OK. Гейты mlxfwutil (молчаливые релокации устранены: verify FAIL
  burn-order + предзаписной отказ inject/repack rc 2 c `--unsafe-relocation`
  research-bypass'ом, safe-relocation планировщиком, автознак 0xA0) —
  `docs/250-re/100-formats/050-fs4-burn-order.md` §3; тесты
  `tests/test_burn_order.py`.

## Приложение: артефакты цикла (build/)

| ver | файл | md5 | diff |
|---|---|---|---|
| stock | `refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin` | `a8c60c90473078288b01009c7cad471b` | — |
| v1 | `build/4030-cda-patched.bin` | `90203cd6f8e7a44279e08e222632a5c2` | 35 байт vs stock |
| v2 | `build/4030-cda-patched2.bin` | `f96b3a324c6be544a27c40374ac1a50f` | 7 байт vs v1 |
| v3 | `build/4030-cda-patched3.bin` | `082e9678b54d0512cec2f155037e82b7` | 34 байта vs stock |
| v4 | `build/4030-cda-patched4.bin` | `e08d4d9f274e81da57c2e7a991744157` | v3 + GUID/MAC (DTOC) + 2-строчный коммент (.ini, **relocation 0x30→0x557660**) — CORRUPTION |
| v5 | `build/4030-cda-patched5.bin` | `45755b80e4000b0df161c88b894ad12f` | v3 + GUID/MAC (DTOC) + 1-строчный коммент (.ini **без relocation**, 0x908≤0x928) — **ФИНАЛЬНЫЙ** |

ITOC entry 0x03 (sec_crc/entry_crc, цепочка stock→v1→v2→v3):
`0x29fc/0x7ebf → 0xb724/0x0b6e → 0x2b7d/0xdc1a → 0x1844/0xbd8f` (журнал
2026-09-20 §26/§28; опечатка «0xb7ac» в §23 журнала — фактически 0xb724).
