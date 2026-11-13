#!/usr/bin/env python3
"""Полный дизасм MAIN_CODE CX-6 Dx в текст с нормализацией branch/call-таргетов.

Порт secfw-прецедента (scripts/secfw/fulldis.py) под RE-базу cx6dx-securefw
(build/cx6dx-main03-dc.bin из extract_main03.py). Каждая строка:
"<dc-офсет> <слово BE> <дизасм>"; таргеты call/jump/b.t/b.f заменены на TGT.

Дополнение порта — контроль качества декода (гейт Шага 1 брифа): в конце
печатаются статистика декода (% слов с известным op, гистограмма unknown-op
для профиля cx6dx) и граница код-региона (блочный скан плотности декода;
прецедент CX-5: код-регион ~[0..0x349e30) при blob 0x398980). Запуск:

  python3 scripts/cx6secfw/fulldis.py build/cx6dx-main03-dc.bin build/cx6dx.dis
"""
import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

BLOCK = 0x10000


def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, "rb").read()
    norm = re.compile(r"^(call|jump) 0x[0-9a-f]+$|^(b\.[tf]\.0x[0-9a-f]+) zero,0x[0-9a-f]+$")
    unknown = collections.Counter()
    known = total = 0
    block_known = collections.Counter()
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
            total += 1
            if s.startswith("op0x"):
                unknown[s[4:6]] += 1
            else:
                known += 1
                block_known[off // BLOCK] += 1
    print("done", dst)
    pct = 100.0 * known / total
    print(f"decode: {known}/{total} words = {pct:.1f}% known-op (whole blob)")
    print("unknown-op histogram:", sorted(unknown.items()))
    blocks = sorted(block_known)
    peak = max((block_known[b] for b in blocks), default=0)
    print(f"peak block known words: {peak}")
    printable = [sum(32 <= b <= 126 for b in data[i:i + BLOCK])
                 for i in range(0, len(data), BLOCK)]
    thr = BLOCK // 2
    pools, start = [], None
    for i, p in enumerate(printable + [0]):
        if p >= thr and start is None:
            start = i
        elif p < thr and start is not None:
            pools.append((start * BLOCK, i * BLOCK))
            start = None
    print("string/data pools (printable>=50% blocks):",
          [f"[{a:#x},{b:#x})" for a, b in pools] or "none")
    pool_blocks = {i for a, b in pools for i in range(a // BLOCK, b // BLOCK)}
    cw = sum((BLOCK // 4 if (i + 1) * BLOCK <= len(data)
              else (len(data) - i * BLOCK) // 4)
             for i in range(len(printable)) if i not in pool_blocks)
    ck = sum(block_known[b] for b in blocks if b not in pool_blocks)
    print(f"code-region decode (blob minus pools): {ck}/{cw} words = "
          f"{100.0 * ck / cw:.1f}% known-op")


if __name__ == "__main__":
    main()
