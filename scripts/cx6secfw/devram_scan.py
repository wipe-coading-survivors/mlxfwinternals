#!/usr/bin/env python3
"""Скан ld.i/st.i-сайтов по индексам внутреннего RAM (task-03).

ld.i RD,imm16 → RAM[imm<<2]; st.i RT,imm11 → RAM[imm<<2]. Ищем всех
читателей/писателей заданных слов состояния (0xc355, 0xd840, 0xc01a,
0xc110, 0xc112, 0xc3ff, 0xd7c1, 0xd882, 0xc980-аналоги и т.п.) и
выводим окно ±6 слов вокруг каждого сайта для контекста.

  python3 scripts/cx6secfw/devram_scan.py 0xc355 0xd840 ...
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

BLOB = "build/cx6dx-main03-dc.bin"
LD = re.compile(r"^ld\.i r\d+,0x([0-9a-f]+)$")
ST = re.compile(r"^st\.i r\d+,0x([0-9a-f]+)$")


def main():
    idxs = {int(a, 0) for a in sys.argv[1:]}
    data = open(BLOB, "rb").read()
    words = {}
    for off in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[off:off + 4], "big")
        s = disasm(w, off)
        m = LD.match(s) or ST.match(s)
        if m and int(m.group(1), 16) in idxs:
            words[off] = s
    lo = None
    for off in sorted(words):
        if lo is not None and off - lo > 28:
            print("    ...")
        for ctx in range(max(0, off - 24), min(len(data) - 3, off + 28), 4):
            if ctx in words:
                print(f"{ctx:08x} {words[ctx]:24s} <<<")
            else:
                ww = int.from_bytes(data[ctx:ctx + 4], "big")
                ss = disasm(ww, ctx)
                print(f"{ctx:08x} {ss}")
        lo = off
    print("sites:", {hex(o): s for o, s in sorted(words.items())})


if __name__ == "__main__":
    main()
