# Gate specs — глава 3 (transceiver-ib-ch3-ghidra-gate)

Спеки патчей гейта (section 3, MAIN_CODE dc offsets). Базовый образ
каждой спеки — образ линейки `build/4030graft*.bin` (gitignored,
воспроизводим: graft = 4030-код + ACA-бордполя + port1-VPI + GUID);
`expected_before` в каждой спеке самопроверяется против базы
(`scripts/probes/cable_gate_patch.py --check`).

| Спека | ID | База (линейка) | Вердикт live |
|---|---|---|---|
| ch3-gate-spec.json | C4 | graft | refuted (геттер cap не у дел) |
| ch3-gate-spec-c6.json | C6 | graft | display-only (SCS 0x1f) — опционален |
| ch3-gate-spec-c1.json | C1 | graft+C6 | harmful (ломает PDDR) — откачен |
| ch3-spec-c4c6.json | C4C6 | graft+vpi0 | refuted (bring-up не геттер) |
| ch3-spec-c7.json | C7 | vpi0-c4c6 | refuted (зеркало B не потребитель) |
| ch3-spec-c8.json | C8 | vpi0-c4c6-c7 | refuted (sink не вызывается) |
| ch3-spec-c9a*.json | C9a/C9a2 | c7/c8 линейки | инъекция-дамп (диагностика, метод docs/250-re/120-irisc/025-boot-injection.md) |
| ch3-spec-c12.json | C12 | vpi0-c4c6-c7-c8 | **CONFIRMED — гейт снят** |
| ch3-spec-c12min.json | C12MIN | graft | **ФИНАЛ: минимальный образ = graft + 1 слово** |

Финальные образы: `4030graft-c12min.bin` (md5 51f3f727…) /
`4030graft-c12min-bazzite.bin` (md5 ed3fcb3e…) — см. docs/250-re/100-formats/070-transceiver-eeprom.md.
