#!/usr/bin/env python3
"""Индекс call/jump по блобу MAIN_CODE 8008-RE-базы (сырые таргеты).

Xref-ходьба от якорей журнала task-03 (§2.4: xref'ы desc-init 0x1080c4,
слот-ридер; §4.1: xref'ы error-постера 0x1b4948, desc-сеттера 0x1d5584).
Запуск из корня репо:

  python3 scripts/secfw/callidx.py [target-substr] [blob]

(blob по умолчанию build/secfw-main03-dc.bin; без target — все call/jump).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

BLOB = sys.argv[2] if len(sys.argv) > 2 else "build/secfw-main03-dc.bin"
data = open(BLOB, "rb").read()
tgt = sys.argv[1] if len(sys.argv) > 1 else None
for off in range(0, len(data) - 3, 4):
    w = int.from_bytes(data[off:off+4], "big")
    s = disasm(w, off)
    if s.startswith("call ") or s.startswith("jump "):
        if tgt is None or tgt in s:
            print("%08x  %s" % (off, s))
