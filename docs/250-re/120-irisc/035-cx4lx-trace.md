# 035. Trace-машина 14.32: iTrace из кода (CX-4 Lx)

> Источник: отчёт `docs/superpowers/reports/cx4lx-detour-l3.md` (RE
> trace-машины, вердикты L3), журнал
> `docs/superpowers/journal/2026-10-11-cx4lx-detour-l3-task-01.md`;
> эмпирика вооружения/ринга — фаза VII
> (`docs/superpowers/reports/cx4lx-detour-b{0,1,1b,2}.md`, журналы
> `docs/superpowers/journal/2026-10-11-cx4lx-detour-b*-task-01.md`);
> хелпер — `scripts/probes/cx4lx-detour/l3_trace_recon.py`. Карта —
> `CARD_CX4LX_BCAT` (bazzite, 04:00.0).
> Связи: каркас/геометрия детура → `030-cx4lx-detour.md`; runtime-хук на
> emit-семье → `040-cx4lx-hook.md`; boot-окно/driverless-арм и формат
> ринга → `045-cx4lx-boot-window-cablepath.md`; dump-цикл (emit7-канал C) →
> `050-cx4lx-dump-cycle.md`; семантика масок/классов iTrace (CX-5) →
> `docs/250-re/100-formats/065-fw-trace.md`; рецепт трассировки →
> `docs/850-howto/150-fw-trace.md`.

Семья trace-машины 14.32 отличается от 4030-лейаута (раздельный GATE вместо
inline):

| элемент | dc | конвенция |
|---|---|---|
| GATE | 0x5f90 | r4=class-маска, r5=level → r4=bool; mask = local RAM **w2**, level = **w3** (L≥2 обходит маску; w3>>16 = log_delay/ts-update) |
| emit1..4, emit0 | 0x603c/0x6064/0x6090/0x6008/0x6188 | **r4 = rt-строка** (насквозь), парамы r5..r8; обёртка стортит парамы в стек-массив |
| emit7 | **0x63bc** | **7 слов/событие** (клобберит r10/r11) |
| CORE | 0x6124 | кадр по 8 слов: сл.0 = строка, далее парамы; ptr CSR0x8, data CSR0xC |

- Сайт вызова: `r4=class; r5=level; call GATE; b.t skip; r4=str` (`addi`
  lo + `addi.hi` hi<<16, **hi = hi16 + carry от lo bit15**); парамы;
  `call emitN`. Конвенции кодирования — `010-isa.md` (addi.hi carry),
  скилл `irisc-asm`.
- Класс/уровень в запись НЕ входят — гейт чисто FW-шний; прямой call emit
  пишет в ринг безусловно. Clobber-сет emit-пути: r3, r5..r9 (+r10/r11 у
  emit6/7); r17..r23 callee-saved.
- **Boot-emit невозможен в принципе**: ринг в host-RAM аллоцирует драйвер
  ПОСЛЕ FW-boot → записи до настройки теряются; ftrace-буфер ребута не
  переживает. Вывод: эмиссия — только runtime-хук (`040`).
- db0 (strings): rt = dc + 0x800000 (`005-endian-addressing.md` §2),
  диапазон dc `[0x2d6900, 0x31b000)` (MTRC_CAP: rt 0x00ad6900, size
  0x44a00). Мёртвые строки для маркеров: скан на 0 загрузчиков константы
  (addi/addi.hi любых регистров).
- Дельты vs CX-5 (4030): owner-PF единственная (флипа нет); PDDR-маркер
  0x5031 на 14.32 не засвидетельствован — верифицировать до использования
  как гейта `[постулат]`.
- Формат ринга (RE по живому дампову, фаза VII): записи 8B BE
  [hdr][data], типы 0xa2/0xa3 (string-слова, event_id) / 0xff (timestamp),
  tdsn/tmsn в hdr[15:0]; CORE-кадр побит на записи — `045` §1.

Применения: runtime-хук v3 (emit2/emit1, `040`), H-AN/H-DEC маркеры
cable-path (emit5/emit2, `045` §2), параметризованный dump-стаб (emit7,
`050`).
