#!/usr/bin/env python3
"""Окно НОРМАЛИЗОВАННОГО дизасма (таргеты → TGT) по .dis-файлам 8008/4030.

Сравнение 8008-окон с 4030-эквивалентами «бок о бок» без шума релокации
адресов (журнал task-03 §1, примечание о mode_chk: код идентичен, отличается
только адрес fmt-строки). Запуск из корня репо:

  python3 scripts/secfw/wdis.py <8008|4030> <lo-hex> <hi-hex> [8008.dis] [4030.dis]
"""
import sys

DIS_A = sys.argv[4] if len(sys.argv) > 4 else "/tmp/opencode/t3/8008.dis"
DIS_B = sys.argv[5] if len(sys.argv) > 5 else "/tmp/opencode/t3/4030.dis"

dis = {}
for p, tag in ((DIS_A, "8008"), (DIS_B, "4030")):
    d = {}
    for ln in open(p):
        a, b, c = ln.split(" ", 2)
        d[int(a, 16)] = c.rstrip("\n")
    dis[tag] = d
lo = int(sys.argv[2], 16) & ~3
hi = int(sys.argv[3], 16)
tag = sys.argv[1]
while lo < hi:
    print(f"{lo:08x}  {dis[tag].get(lo, '<?>')}")
    lo += 4
