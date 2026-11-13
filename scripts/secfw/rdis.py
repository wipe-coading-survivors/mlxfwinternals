#!/usr/bin/env python3
"""Окно сырого (ненормализованного) дизасма блоба MAIN_CODE 8008-RE-базы.

Источник всех дизасм-выписок журнала task-03 (§2-§4: RSA-ветка, компаратор,
слот-ридер, customIV-набор, хендлеры MCC). Запуск из корня репо:

  python3 scripts/secfw/rdis.py <lo-hex> <hi-hex> [blob]

(blob по умолчанию build/secfw-main03-dc.bin — путь параметризован, логика
не менялась; для 4030-стока передайте путь выгрузки extract_main03.py).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

BLOB = sys.argv[3] if len(sys.argv) > 3 else "build/secfw-main03-dc.bin"
data = open(BLOB, "rb").read()
lo = int(sys.argv[1], 16) & ~3
hi = int(sys.argv[2], 16)
while lo < hi:
    w = int.from_bytes(data[lo:lo+4], "big")
    print("%08x  %08x  %s" % (lo, w, disasm(w, lo)))
    lo += 4
