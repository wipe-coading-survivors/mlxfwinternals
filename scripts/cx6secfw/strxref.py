#!/usr/bin/env python3
"""Поиск загрузчиков адреса (addi+addi.hi-пара) строки/объекта MAIN_CODE CX-6.

Порт secfw/strxref.py под базу CX-6: строка лежит в блобе по dc-адресу S,
rt-адрес = S + load_base (0x21000000 для 22.50.1002, см. rt_calib.py);
загрузка — addi rX,zero,lo16 + addi.hi rX,rX,hi. Печатаются все pair-сайты
(точный rt), не только call-сайты. Запуск из корня репо:

  python3 scripts/cx6secfw/strxref.py [--base 0x21000000] <dc-hex>... [blob]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402
from scripts.irisc.irisc_dis import s16  # noqa: E402

BLOB = "build/cx6dx-main03-dc.bin"
BASE = 0x21000000

args = sys.argv[1:]
blob = BLOB
if args and args[0] == "--base":
    BASE = int(args[1], 0)
    args = args[2:]
if args and args[-1].endswith(".bin"):
    blob = args.pop()

data = open(blob, "rb").read()
targets = [int(a, 16) + BASE for a in args]
w = lambda o: int.from_bytes(data[o:o + 4], "big")
for o in range(0, len(data) - 8, 4):
    ww = w(o)
    if (ww >> 26) & 0x3F not in (0x00, 0x01):
        continue
    rd = (ww >> 16) & 0x1F
    lo = ww & 0xFFFF
    for k in range(1, 4):
        wp = w(o + 4 * k)
        if (wp >> 26) & 0x3F not in (0x02, 0x03):
            continue
        if ((wp >> 21) & 0x1F) != rd:
            continue
        val = (((wp & 0xFFFF) << 16) + s16(lo)) & 0xFFFFFFFF
        for t in targets:
            if val == t:
                print("%08x  addi lo=%#x -> dc %#x" % (o, s16(lo), t - BASE))
                print("%08x  %s" % (o + 4 * k, disasm(wp, o + 4 * k)))
        break
