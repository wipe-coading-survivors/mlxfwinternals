# 130-ncsi-smbus

**Статус:** seed
**Цель:** разобраться/разработать поддержку **NC-SI (DMTF) + SMBus** для
ConnectX-карт (и возможно свитчей) — штатный out-of-band канал управления
BMC ↔ карта (владелец, 2026-10-29).
**Критерии закрытия:** NC-SI-след в mstflint/refs разобран и написана
спецификация «что ждать на SMBus» (различены NC-SI-канал vs
«I2C-Compatible»-интерфейс); SMBus-проба карты выполнена live (BMC и/или
CH341: scan по адресам, GET_CHANNEL_STATUS, slave-адрес; поколения
CX-4/5/6, пины); решение по цели — NC-SI c BMC для out-of-band
управления/восстановления карты без живого хоста (связка с
`docs/010-roadmap/120-mtusb-i2c.md`).
**Фазы/задачи:**
- [ ] Офлайн (суб-агент + журнал): NC-SI-след в mstflint/refs (что
      известно о реализации карты: slave-адрес, каналы, команды) +
      DSP0266 → спецификация «что ждать на SMBus»; различить NC-SI-канал
      vs «I2C-Compatible»-интерфейс (одна шина? те же адреса?)
- [ ] Live (суб-агент + явное go): SMBus-проба карты (BMC и/или CH341:
      scan по адресам, NC-SI GET_CHANNEL_STATUS, slave-адрес) — отвечает
      ли карта, на каком поколении (CX-4/5/6), где пины (test points на
      плате)
- [ ] Цель (решение после (а)-(б)): NC-SI c BMC для out-of-band
      управления/восстановления карты без живого хоста (связка с
      `docs/010-roadmap/120-mtusb-i2c.md`)
**Семёна:** TODO-семя «NC-SI + SMBus: out-of-band канал управления
(BMC ↔ карта)» (2026-10-29, владелец).
**Связи:** `refs/docs/ethernet-adapters-programming-manual.txt`
(§1.2.1.2/§1.2.1.3), DMTF NC-SI DSP0266, `refs/src/mstflint`
(`tools_layouts/adb/prm/hca/ext/hca_cap_table.adb:1335`); наш I2C-тулинг
(CH341, `ch341i2c.py`) + BMC (ipmi-ops); тот же физический интерфейс —
`docs/010-roadmap/120-mtusb-i2c.md`.

# NC-SI + SMBus: out-of-band канал управления (BMC ↔ карта)

По programming-manual (§1.2.1.2, p. 28) карта поддерживает **NC-SI v2.0**;
детали вендор закрывает («Please contact Mellanox Technologies») — публична
только сама спека протокола (DMTF DSP0266: SMBus-транспорт, RD/WR,
RBTX/RBRX, GET_CHANNEL_STATUS, slave-адрес). Связь с
`docs/010-roadmap/120-mtusb-i2c.md`: тот же физический I2C/SMBus-интерфейс
карты (programming-manual §1.2.1.3: I2C-compatible, slave 0x48,
out-of-band/HW-debug, две шины) — NC-SI = *протокол* на нём для BMC,
MT-USB = *мост* I2C-мастера (наш CH341/347) к тем же пинам.

Стартовые точки:
- programming-manual §1.2.1.2/§1.2.1.3 (NC-SI 2.0 / I2C-compatible)
- refs/src/mstflint: `tools_layouts/adb/prm/hca/ext/hca_cap_table.adb:1335`
  — `local_mng_port`/`local_mng_port_valid` (порт → локальный BMC через
  NC-SI) — в mstconfig-параметрах не найдено (проверить на живых картах
  через HCA_CAP)
- DMTF NC-SI DSP0266 (публичная спека протокола)
- наш I2C-тулинг (CH341, `ch341i2c.py`, раздел «Трансиверы») + BMC
  (ipmi-ops)
