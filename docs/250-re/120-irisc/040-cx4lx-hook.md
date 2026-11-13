# 040. Runtime-хук v3: сайт трассировки в register-хэндлере (CX-4 Lx)

> Источник: отчёт `docs/superpowers/reports/cx4lx-detour-l3.md` (v3,
> вердикт L3), журнал
> `docs/superpowers/journal/2026-10-11-cx4lx-detour-l3-task-01.md`;
> билдер — `scripts/probes/cx4lx-detour/build_detour_v3.py`. Карта —
> `CARD_CX4LX_BCAT` (bazzite, 04:00.0, образ `cx4lx-detour-v3`; банки
> позднее перезаписаны — текущее состояние `050` §3).
> Связи: каркас/геометрия/cave → `030-cx4lx-detour.md`; конвенции
> emit-семьи и clobber-сет → `035-cx4lx-trace.md`; dispatch-карта
> (хук-кандидаты H0/H2/H6) → `030` §4; сборка/burn →
> `docs/850-howto/190-irisc-build-burn.md`.

Хук (устойчивый рабочий прецедент, v3): подмена call-сайта трассировки в
register-хэндлере **0xd3804** (команда из CR w0x801, reg_id = word>>16;
сайт: GATE(ICMD бит 26, L1) → rt 0x00ada88c → emit2 `call 0x6064`
@dc **0xd3850**; r5..r10 после сайта не читаются):

- патч сайта: `94fcca05` → `940924da` (`call 0x31cbb8` — стаб в кейве
  `0x31cba0`, см. `030` §2);
- стаб (8 слов, после v1-блока; итого 14/24 слов кейва):

```
csr.r r10,csr0xbc      ; сохранить линк (call = link-register csr0xbc!)
call 0x6064            ; stock emit2 ПЕРВЫМ — аргументы r4/r5/r6 уже на месте
addi r4,zero,0xa612    ; rt 0x00ada612 (мёртвая строка, lo s16)
addi.hi r4,r4,0xae     ; hi = hi16 + carry
addi r5,zero,0xbad     ; наш парам
call 0x603c            ; emit1 — наша строка
csr.w r10,zero,0xbc    ; восстановить линк
ret.d                  ; возврат на сайт+4
```

Ключ: **stock emit первым** (потребляет готовые аргументы — ноль
save/restore); линк в r10 (вне clobber-сета emit-пути — `035`); наше
событие за тем же гейтом сайта (маска ICMD → видно; mask 0 → тишина).
Триггер = любая register-команда (mstreg/mstflint rb/драйверный поллинг) —
дёшево и часто.

Верификация v3-live: `memory_profile = 0xbad` ×104 = 1:1 к командам окна;
контроли v1/v2 = 0; restore-silence = 0.
