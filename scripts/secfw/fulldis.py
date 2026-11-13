#!/usr/bin/env python3
"""Полный дизасм MAIN_CODE в текст с нормализацией branch/call-таргетов.

Вход для кросс-карты (relomap_code.py) и релокации якорей
(reloc_anchors*.py, wdis.py) журнала task-03 §1. Каждая строка:
"<dc-офсет> <слово BE> <дизасм>"; таргеты call/jump/b.t/b.f заменены на TGT
(релокация адресов между 8008 и 4030 не должна считаться контентной дельтой).
Запуск из корня репо (блобы — из extract_main03.py):

  python3 scripts/secfw/fulldis.py build/secfw-main03-dc.bin /tmp/opencode/t3/8008.dis
  python3 scripts/secfw/fulldis.py /tmp/opencode/t3/cda4030-main03-dc.bin /tmp/opencode/t3/4030.dis
"""
import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
norm = re.compile(r"^(call|jump) 0x[0-9a-f]+$|^(b\.[tf]\.0x[0-9a-f]+) zero,0x[0-9a-f]+$")
with open(dst, "w") as f:
    for off in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[off:off + 4], "big")
        s = disasm(w, off)
        m = norm.match(s)
        if m:
            if m.group(1):
                s = m.group(1) + " TGT"
            else:
                s = m.group(2) + " zero,TGT"
        f.write("%08x %08x %s\n" % (off, w, s))
print("done", dst)
