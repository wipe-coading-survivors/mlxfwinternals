# 120-mtusb-i2c

**Статус:** seed
**Цель:** разработать **аналог MT-USB (MTUSB-1)** — out-of-band доступ к
ConnectX-картам (и возможно свитчам) через **I2C** через программатор
**CH341/CH347** (владелец, 2026-10-29).
**Критерии закрытия:** разобран MTUSB/I2C-бэкенд mstflint и написана
спецификация для CH341/347-аналога (включая свитчи — есть ли тот же
I2C-путь); подключение CH341/347 к I2C-пинам карты проверено live
(обнаружение ACK/чтение); реализован I2C-транспорт (CH341 и CH347) с
обменом по спецификации — доступ уровня mstflint (минимум `q`/дамп; цель —
burn/restore карты без живого хоста).
**Фазы/задачи:**
- [ ] Офлайн (суб-агент + журнал): разобрать MTUSB/I2C-бэкенд mstflint
      (refs/src/mstflint: протокол обмена по I2C — адреса/команды/фрейминг,
      что доступно: `q`/дамп/`burn`/FNP-restore?) + I2C-интерфейс карты по
      programming-manual §1.2.1.3 и MFT-doc (глава MTUSB-1) → спецификация
      для CH341/347-аналога. Свитчи — отдельно: есть ли у них тот же I2C-
      путь (мануалы/железо).
- [ ] Железо: подключение CH341/347 к I2C-пинам карты (test points,
      pinout, уровни, slave-адрес) + проверка обнаружения (ACK/чтение) —
      live только суб-агент + явное go (AGENTS.md)
- [ ] Реализация: I2C-транспорт (расширение `ch341i2c.py` / новая тулза,
      CH341 и CH347) + обмен по спецификации → доступ уровня mstflint
      (минимум `q`/дамп; цель — burn/restore карты без живого хоста)
**Семёна:** TODO-семя «Аналог MT-USB: out-of-band доступ через I2C»
(2026-10-29); перспектива при старте — отдельный роадмап в корне репо (по
принципу `docs/010-roadmap/100-irisc.md`); пока — seed.
**Связи:** `refs/src/mstflint` (MTUSB/I2C-бэкенд:
`mft_sdk/mft_sdk_discovery.cpp`, `mtcr_ul/*` — как именно идёт обмен) +
`refs/docs/ethernet-adapters-programming-manual.txt` (§1.2.1.3) + MFT-doc
(глава «MTUSB-1 USB to I2C Adapter»: подключение); тот же физический
интерфейс — `docs/010-roadmap/130-ncsi-smbus.md`.

# Аналог MT-USB: out-of-band доступ через I2C (CH341/347)

Штатный MTUSB-1 — USB-to-I2C адаптер Mellanox: `mst status` →
`/dev/mst/mtusb-1` («USB to I2C adapter as I2C master»), через него
работают `mstflint q`/`burn` (ограничение MFT-doc: до 45 мин,
`-no_flash_verify` для ускорения). I2C-интерфейс карты — штатный
out-of-band/отладочный канал (programming-manual §1.2.1.3, p. 28:
out-of-band access / HW debug / Mellanox debug tools, slave-адрес 0x48,
master/slave, две шины на редундантность).

Стартовое положение (уже в репо): userspace I2C-мастер CH341
`scripts/ch341i2c.py` (pyusb; bulk-stream 0xAA, verify-by-read-back) +
контейнер `docker/ch341i2c.containerfile` + `make ch341i2c-run ARGS="…"`
(раздел «Трансиверы», 2026-10-04, журнал
`2026-10-04-ch341-programmer-bringup.md`); борты с CH341 в лабе
(PACBTECH, 1a86:5512). CH347 — второй кандидат (USB-UART+GPIO, I2C
bit-bang).
