#!/usr/bin/env python3
"""Дизамбигуация якорей длинными нормализованными окнами (W=16/24).

Воспроизводит уточнения журнала task-03 §1: secure_chk(0x4000) → 0x1d0030
(W=24), patch_gate_ini → 0x1cfe6c, fw_burn_fsm → 0x1d5b78 (W=16),
digest_loop → 0x1d2c94, itoc_scan → 0x195a0; и «NO MATCH» mode_chk(0x8000)
при W=24 (код идентичен только с точностью до адреса fmt-строки трейса —
см. примечание §1 журнала). Запуск из корня репо:

  python3 scripts/secfw/reloc_anchors_long.py [8008.dis] [4030.dis]
"""
import sys

DIS_A = sys.argv[1] if len(sys.argv) > 1 else "/tmp/opencode/t3/8008.dis"
DIS_B = sys.argv[2] if len(sys.argv) > 2 else "/tmp/opencode/t3/4030.dis"

def load(p):
    lines = open(p).read().splitlines()
    off, txt = [], []
    for ln in lines:
        a, _, c = ln.split(" ", 2)
        off.append(int(a, 16)); txt.append(c)
    return off, txt

oa, ta = load(DIS_A)
ob, tb = load(DIS_B)
o2i_b = {o: i for i, o in enumerate(ob)}
for name, a, W in [("ini_chk_secure_0x4000", 0x1cf910, 24), ("ini_chk_mode_0x8000", 0x1cfa5c, 24),
                   ("patch_gate_ini", 0x1cf74c, 24), ("fw_burn_fsm", 0x1d5458, 16),
                   ("digest_loop", 0x1d2574, 16), ("itoc_scan", 0x1957c, 16)]:
    i = o2i_b[a]
    win = tb[i:i+W]
    hits = [oa[k] for k in range(len(ta)-W+1) if ta[k:k+W] == win]
    print(f"{name:24s} 4030:{a:#x} W={W} -> {', '.join(f'{h:#x}(+{h-a:#x})' for h in hits) or 'NO MATCH'}")
