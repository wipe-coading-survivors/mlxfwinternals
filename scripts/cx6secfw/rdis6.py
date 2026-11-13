#!/usr/bin/env python3
"""Окно сырого дизасма CX-6 RE-базы с разрешёнными таргетами (task-03).

fulldis.py нормализует таргеты call/jump/b.t/b.f в TGT (для кросс-сравнения);
для трассировки verify-цепочки нужны фактические адреса. Здесь слова
декодируются заново из build/cx6dx-main03-dc.bin (декодер scripts.irisc,
база 0x21000000), таргеты печатаются как есть. Опции: диапазон lo..hi,
--xref <dc> (кто ссылается на адрес: call/jump-сайты из индекса fulldis-типа
сканирования). Запуск из корня репо:

  python3 scripts/cx6secfw/rdis6.py <lo-hex> <hi-hex>
  python3 scripts/cx6secfw/rdis6.py --xref <dc-hex> [lo-hex hi-hex]
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

BLOB = "build/cx6dx-main03-dc.bin"


def main():
    args = sys.argv[1:]
    xref = None
    if args and args[0] == "--xref":
        xref = int(args[1], 16)
        args = args[2:]
    data = open(BLOB, "rb").read()
    if xref is not None:
        callers = defaultdict(list)
        pat = re.compile(r"^(call|jump) 0x([0-9a-f]+)$")
        for off in range(0, len(data) - 3, 4):
            w = int.from_bytes(data[off:off + 4], "big")
            if (w >> 26) & 0x3F != 0x25:
                continue
            m = pat.match(disasm(w, off))
            if m:
                t = int(m.group(2), 16)
                callers[t].append(off)
        sites = callers.get(xref, [])
        print(f"xref -> {xref:#x}: {len(sites)} call/jump sites")
        for o in sites:
            print(f"  site {o:#x}")
        return
    lo = int(args[0], 16) & ~3
    hi = int(args[1], 16)
    while lo < min(hi, len(data)):
        w = int.from_bytes(data[lo:lo + 4], "big")
        print(f"{lo:08x} {w:08x} {disasm(w, lo)}")
        lo += 4


if __name__ == "__main__":
    main()
