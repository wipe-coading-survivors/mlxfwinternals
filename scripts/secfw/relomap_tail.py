#!/usr/bin/env python3
"""Кросс-карта хвоста-данных MAIN_CODE 8008 ↔ 4030 (raw-byte resync, RS=64).

Воспроизводит числа журнала task-03 §1 для хвоста: «82.7% совпадения,
68 малых зон» на интервале 8008[0x349e30..0x398928) / 4030[0x3491f0..0x397d68)
(границы — от код-карты relomap_code.py). Запуск из корня репо:

  python3 scripts/secfw/relomap_tail.py [8008.bin] [4030.bin] [tailmap.json]

(пути по умолчанию — как в сессии журнала; блобы — из extract_main03.py).
"""
import sys
import json

A_PATH = sys.argv[1] if len(sys.argv) > 1 else "build/secfw-main03-dc.bin"
B_PATH = sys.argv[2] if len(sys.argv) > 2 else "/tmp/opencode/t3/cda4030-main03-dc.bin"
OUT = sys.argv[3] if len(sys.argv) > 3 else "/tmp/opencode/t3/tailmap.json"

A = open(A_PATH, "rb").read()
B = open(B_PATH, "rb").read()
a0, b0 = 0x349e30, 0x3491f0
a1, b1 = 0x398928, 0x397d68
A, B = A[a0:a1], B[b0:b1]
RS = 64
idx = {}
for i in range(0, len(B) - RS + 1, 4):
    idx.setdefault(B[i:i+RS], []).append(i)
d = 0
zones = []
i = 0
matched = 0
while i < len(A):
    j = i + d
    if j >= len(B):
        zones.append((i, len(A), j, len(B), None)); break
    n = 0
    m = min(len(A) - i, len(B) - j)
    while n < m and A[i+n] == B[j+n]:
        n += 1
    matched += n
    ei, ej = i + n, j + n
    if ei >= len(A) or ej >= len(B):
        break
    found = False
    for k in range(0, 0x8000, 1):
        i2 = ei + k
        if i2 + RS > len(A):
            break
        c = idx.get(A[i2:i2+RS])
        if c:
            j2 = min(c, key=lambda x: abs((x - i2) - d))
            d2 = j2 - i2
            zones.append((ei, i2 + RS, ej, j2 + RS, d2 - d))
            d = d2
            i = i2 + RS
            matched += RS
            found = True
            break
    if not found:
        zones.append((ei, len(A), ej, len(B), None)); break
print(f"tail matched {matched}/{len(A)} = {matched/len(A)*100:.1f}%  zones={len(zones)}")
for z in zones:
    la, lb = z[1]-z[0], z[3]-z[2]
    if la > 0x40 or lb > 0x40 or z[4] is None:
        print(f"  8008[{a0+z[0]:#x}..{a0+z[1]:#x}) 4030[{b0+z[2]:#x}..{b0+z[3]:#x}) l8={la:#x} l4={lb:#x} shift={(z[4]*4) if z[4] is not None else 'TAIL'}")
json.dump({"a0": a0, "b0": b0, "zones": zones}, open(OUT, "w"))
