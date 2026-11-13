# 170-factory-image

**Статус:** seed
**Цель:** тулом готовить **factory-образ** — (кастомный) образ для карты с
**пустой флешкой**, содержащий **base GUID/MAC** и **кастомный PSID**: после
прошивки карта сразу имеет полную идентичность (PSID + GUID/MAC), без
отдельного live-шага.
**Критерии закрытия:** реализована сабкоманда `mlxfwutil factory <base.bin>
--guid <G> --mac <M> --psid <P> -o <out.bin>` (base GUID/MAC + кастомный
PSID встроены в образ); режим портов задаётся из самого образа без
mstconfig; burn-рецепт на пустую флешку отработан (флаги + verify:
PSID/GUID/MAC, netdev MAC + ibstat Node GUID, не только `q`); пункты
seed-скоупа из «Фазы/задачи» учтены.
**Фазы/задачи:** (что учесть при проектировании, seed-скоуп)
- где в образе/флеше живут base GUID/MAC (какая секция/область; куда пишет
  `mstflint sg`) — сверить с `docs/550-poc/100-mlxfwutil/020-patch-matrix.md` (маппинг секций); фактический путь —
  инжект `mlxfwutil.py guides` (mDevInfo+MFG_INFO, live-проверен 2026-09-23);
  `--use_image_guids` mstflint — FS2-only и НЕ используется
- сабкоманда `mlxfwutil factory <base.bin> --guid <G> --mac <M> --psid <P> -o
  <out.bin>`: встроить base GUID/MAC + кастомный PSID в образ (PSID — через
  существующую `psid`-логику)
- режим портов **без mstconfig** (в дополнение к `--guids`; точное
  понимание получено 2026-09-13): байт `0x11+0x2b7/0x2bb`
  {b0=net_ib, b1=net_eth, b2=def_ib, b3=def_eth} задаёт режим порта из
  самого образа — `0x0a` = EN (eth-лок), `0x07` = VPI def-IB, `0x0b` =
  VPI def-ETH: после factory-burn порты сразу в нужном режиме, без
  NV-override (исследование t53h/t53i — docs/750-exp/120-eda-ib-node §5.5, docs/550-poc/100-mlxfwutil/020-patch-matrix.md: строка
  0x11 + mstconfig-блок; логи `refs/fw/cx-5-6/t53h-2026-09-13.log`,
  `refs/fw/cx-5-6/t53i-2026-09-13.log`)
- burn-рецепт на пустую флешку: флаги (`-apc`, `-ocr --nofs
  --ignore_dev_data`?; гуиды — уже в образе через `mlxfwutil.py guides`,
  `--use_image_guids` не работает — FS2-only) + verify (PSID/GUID/MAC;
  netdev MAC + ibstat Node GUID, не только `q`)
**Семёна:** TODO-заметка/seed «Factory-образ (mlxfwutil factory)» (заметка
2026-09-10); исходный чекбокс «из этой заметки сделать полноценный раздел в
ROADMAP» закрывается этой карточкой.
**Связи:** `docs/850-howto/100-cross-flash-ops` §9.1, `docs/750-exp/110-dell-base-rework` (T15), `docs/250-re/100-formats/`, `docs/750-exp/120-eda-ib-node` §5.5;
`mlxfwutil.py` (`psid`, `repack`/`patch`, `guides`); логи
`refs/fw/cx-5-6/t53h-2026-09-13.log`, `refs/fw/cx-5-6/t53i-2026-09-13.log`.

# Factory-образ (mlxfwutil factory) — заметка/seed

Сейчас mlxfwutil меняет PSID (`psid`) и собирает кастомный образ
(`repack`/`patch`), но base GUID/MAC ставятся **live** через
`mstflint sg --guid --mac` (docs/850-howto/100-cross-flash-ops §9.1, docs/750-exp/110-dell-base-rework T15); на пустую флешку
`sg` применить не к чему (нет загрузочного образа / device-data) ⇒ GUID/MAC
должны быть **в самом образе**. В дополнение к `--guids` теперь есть и
точное понимание, как **изначально** поставить порты в нужный режим без
mstconfig (байт `0x11+0x2b7/0x2bb` — выше, исследование t53h/t53i,
2026-09-13).
