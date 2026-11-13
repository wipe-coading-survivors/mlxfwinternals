# probes/ — референсные пробники (архив фазы 1)

Статус: **референс/архив**, не продукт. Это инструменты эмпирической
верификации отчётов фазы 1 («отчёт без кода»; плоские docs-отчёты той фазы
растворены 2026-11 — git-история). Продукт
проекта — Rust-тул (фазы 2–5); эти скрипты — его оракул/шпаргалка:
битовые офсеты полей и CRC-цикл сверены с исходниками mstflint
(`refs/src/mstflint`) и проверены на всех образах `refs/fw/` (2026-09-06).

Запуск: `python3 scripts/probes/<имя>.py <образ.bin> [...]`
(без внешних зависимостей, Python 3).

## Скрипты

| Скрипт | Назначение | Раздел отчёта |
|---|---|---|
| `toc_probe.py` | Маги (FS2/3/4/5), поиск ITOC/DTOC, парсинг записей, сверка header/entry/section CRC. Базовый модуль для остальных | docs/250-re/100-formats/ (детекция, FS2/FS3/FS4) |
| `fb_probe.py` | ITOC через HwPointers (устойчиво для вендорских укладок) + секции подписи 0xA0–0xA7 с UUID, IMAGE_INFO, FW_BOOT_CFG (device_id/subsystem) — анализ вендорских образов (Dell/HP/Facebook) | docs/250-re/110-signing/005-mechanism.md, 025-secure-boot.md |
| `sig_probe.py` | Секции подписи + флаги IMAGE_INFO (mcc/signed/secure), PSID/name/desc по набору образов | docs/250-re/110-signing/005-mechanism.md |
| `parse_imageinfo.py` | Дамп IMAGE_INFO + диф FW_BOOT_CFG и секций подписи для пары образов (офсеты захардкожены под пару CX-6Dx AE/AC) | docs/250-re/110-signing/025-secure-boot.md |
| `sign_diff.py` | Байтовые диф-диапазоны пары образов | docs/250-re/110-signing/025-secure-boot.md |
| `verify_sha.py` | Пересчёт SHA-256 (секция 0xA0) по образу с маскировкой; бит-в-бит модель (маски/size) решена — docs/250-re/110-signing/010-payload.md | docs/250-re/110-signing/010-payload.md |
| `inject_guids.py` | Вставка GUID/MAC в factory-образ: mDevInfo (DEV_INFO 0xE1) + копия в 0xE0 + пересчёт sec_crc/entry_crc. **Только offline** — burn блокируется hashes table CRC (docs/750-exp/140-post-fnp-guid-desync §8.7). mlxfwutil.py как библиотека | docs/750-exp/140-post-fnp-guid-desync §8, §8.7 |

## Сводка: где что (дублирование)

| Функция | Где смотреть | Примечание |
|---|---|---|
| Маги, локация ITOC/DTOC, поля записей | `toc_probe` | fb_probe/sig_probe парсят ITOC без сверки CRC |
| header/entry/section CRC | `toc_probe` | единственный со сверкой |
| ITOC через HwPointers | `fb_probe` | **не верифицирован**: на FB-образе не сработал (fallback на поиск заголовка), шаг 16B/u64 против 8B/u32 из docs/150-external/120-syndicate/010-mlx5fw-mlx5cmd.md |
| Секции подписи: что «заполнено» (размеры) | `sig_probe` | |
| Секции подписи: keypair_uuid/payload по layout | `fb_probe` | баг с единым офсетом 0x18 исправлен 2026-09-06 |
| IMAGE_INFO: PSID, флаги, name/desc/prs | `sig_probe` | fb_probe — только PSID |
| FW_BOOT_CFG: device_id/subsystem | `fb_probe` | |
| SHA-256 по образу (0xA0) | `verify_sha` | бит-в-бит модель решена (docs/250-re/110-signing/010-payload.md) |
| Диф пары образов (байты) | `sign_diff` | |
| Диф пары образов (именованные секции) | `parse_imageinfo` | офсеты захардкожены под CX-6Dx AE/AC |
| Вставка GUID/MAC + CRC пересчёт | `inject_guids` | DEV_INFO (crcf=2, без CRC) + 0xE0 (crcf=0, sec_crc). **Не для burn** — hashes table CRC (§8.7) |

## Важно: CRC

`crc16_mlx()` в `toc_probe.py` — побитовое воспроизведение класса
`Crc16` из mstflint. Это **не стандартный** параметризуемый CRC-16
(poly 0x100B / init 0xFFFF / xorout 0xFFFF): входной бит OR-ится в LSB,
полином применяется по старшему биту регистра **до** сдвига.
Реализация «по параметрам» из стандартных библиотек даст другое
значение — см. docs/250-re/100-formats/025-crc.md.
