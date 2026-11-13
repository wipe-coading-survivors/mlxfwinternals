#!/usr/bin/env python3
"""Кросс-карта код-региона MAIN_CODE 8008-RE-база ↔ 4030-CDA (нормализованный
дизасм, resync блочным хешем 48 слов).

Воспроизводит числа журнала task-03 §1: «65.1% слов совпадают нормализованно;
119 зон вставок/удалений; 4226 зон подстановки (0x68040 слов); общий суффикс
22 слова». Входы — .dis-файлы из fulldis.py (пути по умолчанию — как в сессии
журнала, переопределяются аргументами). Запуск из корня репо:

  python3 scripts/secfw/relomap_code.py [8008.dis] [4030.dis] [relomap.json]
"""
import sys
import json
from hashlib import md5

DIS_A = sys.argv[1] if len(sys.argv) > 1 else "/tmp/opencode/t3/8008.dis"
DIS_B = sys.argv[2] if len(sys.argv) > 2 else "/tmp/opencode/t3/4030.dis"
OUT = sys.argv[3] if len(sys.argv) > 3 else "/tmp/opencode/t3/relomap.json"

def load(p):
    lines = open(p).read().splitlines()
    off, txt = [], []
    for ln in lines:
        a, _, c = ln.split(" ", 2)
        off.append(int(a, 16)); txt.append(c)
    return off, txt

oa, ta = load(DIS_A)
ob, tb = load(DIS_B)
A, B = ta, tb
RS = 48

# common suffix
sfx = 0
while sfx < min(len(A), len(B)) and A[len(A)-1-sfx] == B[len(B)-1-sfx]:
    sfx += 1
print(f"common suffix: {sfx} words (8008 {oa[len(A)-sfx]:#x}..  4030 {ob[len(B)-sfx]:#x}..)" if sfx else "no common suffix")

blk = {}
for i in range(0, len(B) - RS):
    h = md5(("\n".join(B[i:i+RS])).encode()).hexdigest()
    blk.setdefault(h, []).append(i)

limA, limB = len(A) - sfx, len(B) - sfx
d = 0
zones, match_words = [], 0
i = 0
while i < limA:
    j = i + d
    if j >= limB:
        zones.append((i, limA, j, limB, None)); break
    n = 0
    m = min(limA - i, limB - j)
    while n < m and A[i+n] == B[j+n]:
        n += 1
    match_words += n
    ei, ej = i + n, j + n
    if ei >= limA or ej >= limB:
        break
    found = False
    for k in range(0, 0x4000):
        i2 = ei + k
        if i2 + RS > limA:
            break
        h = md5(("\n".join(A[i2:i2+RS])).encode()).hexdigest()
        cands = [c for c in blk.get(h, []) if c < limB]
        if cands:
            j2 = min(cands, key=lambda x: abs((x - i2) - d))
            d2 = j2 - i2
            zones.append((ei, i2 + RS, ej, j2 + RS, d2 - d))
            d = d2
            i = i2 + RS
            match_words += RS
            found = True
            break
    if not found:
        zones.append((ei, limA, ej, limB, None)); break

print(f"matched words: {match_words}/{len(A)} = {match_words/len(A)*100:.1f}%  zones={len(zones)}")
subs = [z for z in zones if z[4] == 0]
ins = [z for z in zones if z[4] is not None and z[4] != 0]
print(f"substitution zones (same alignment): {len(subs)}, total words {sum(z[1]-z[0] for z in subs):#x}")
print(f"insert/delete zones (alignment shift): {len(ins)}")
for z in ins:
    print(f"  8008[{oa[z[0]]:#09x}..{oa[min(z[1],len(oa)-1)]:#09x}) 4030[{ob[z[2]]:#09x}..{ob[min(z[3],len(ob)-1)]:#09x}) "
          f"w8={z[1]-z[0]:#6x} w4={z[3]-z[2]:#6x} shift={(z[4])*4:+#x} bytes")
tail = [z for z in zones if z[4] is None]
for z in tail:
    print(f"  UNRESOLVED TAIL 8008[{oa[z[0]]:#x}..{oa[min(z[1],len(oa)-1)]:#x}) 4030[{ob[z[2]]:#x}..{ob[min(z[3],len(ob)-1)]:#x})")
json.dump({"zones": zones, "sfx": sfx, "limA": limA, "limB": limB}, open(OUT, "w"))
