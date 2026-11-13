#!/usr/bin/env python3
"""Калибровка dc↔rt для CX-6 Dx MAIN_CODE (метод 8008-wall-retest / burn-digest).

Шаг 2 брифа task-02: рабочая гипотеза плана `rt = dc + 0x800000` (CX-5)
проверяется и калибруется. Метод (журнал 2026-10-15-8008-wall-retest):

1. load base = ITOC param0 секции 0x03 (cibfw_itoc_entry: «if partition
   type is code then the load address is in here»);
2. консенсус addi/addi.hi пар (op 0x00/0x01 + 0x02/0x03, окно ≤3 слов,
   RS(hi)==RD(lo)): % пар, строящих адреса [base, base+len(dc));
3. точность: пары, попадающие ровно в начала printable-строк;
4. rt-указатели в данных: слова в строковых/данных пулах, равные
   [base, base+len) → dc-цель должна быть function-start'ом (call-таргет
   или пролог) — независимая верификация базы с data-стороны
   (таблицы диспетчеризации хранят rt-адреса хендлеров);
5. sanity call/jump-таргетов (все в [0, len(dc))).

Режим --xref <dc-hex> — все call-сайты на функцию (callidx-порт,
для сверки call-цепочек от якорей). Запуск из корня репо:

  python3 scripts/cx6secfw/rt_calib.py [image] [blob]
  python3 scripts/cx6secfw/rt_calib.py --xref 0x1234 [blob]
"""
import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402
from scripts.irisc.irisc_dis import s16, dis  # noqa: E402

IMG = ("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-VDA_Ax"
       "-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin")
BLOB = "build/cx6dx-main03-dc.bin"
BLOCK = 0x10000


def pairs_scan(dc):
    n = len(dc)
    w = lambda o: int.from_bytes(dc[o:o + 4], "big")
    pairs = []
    for o in range(0, n - 4, 4):
        ww = w(o)
        if (ww >> 26) & 0x3F not in (0x00, 0x01):
            continue
        rd = (ww >> 16) & 0x1F
        lo = ww & 0xFFFF
        for k in range(1, 4):
            j = o + 4 * k
            if j + 4 > n:
                break
            wp = w(j)
            if (wp >> 26) & 0x3F not in (0x02, 0x03):
                continue
            if ((wp >> 21) & 0x1F) != rd:
                continue
            val = (((wp & 0xFFFF) << 16) + s16(lo)) & 0xFFFFFFFF
            pairs.append((o, val))
            break
    return pairs


def call_targets(dc):
    tgts, sites = set(), []
    for o in range(0, len(dc) - 3, 4):
        ww = int.from_bytes(dc[o:o + 4], "big")
        if (ww >> 26) & 0x3F == 0x25:
            s = dis(ww, o)
            t = int(s.split(" 0x")[-1], 16)
            tgts.add(t)
            sites.append((o, t, s.startswith("call")))
    return tgts, sites


def main():
    args = sys.argv[1:]
    if args and args[0] == "--xref":
        blob = args[2] if len(args) > 2 else BLOB
        dc = open(blob, "rb").read()
        want = int(args[1], 16)
        _, sites = call_targets(dc)
        for o, t, is_call in sites:
            if t == want:
                print("%08x  call->%#x" % (o, t) if is_call else
                      "%08x  jump->%#x" % (o, t))
        return
    img_path = args[0] if len(args) > 0 else IMG
    blob = args[1] if len(args) > 1 else BLOB
    dc = open(blob, "rb").read()
    e = mlxfwutil.Image(open(img_path, "rb").read(), img_path).find_entry("ITOC", 0x03)
    base, entry = e.param0, e.param1
    print(f"blob={len(dc):#x} param0(load)={base:#x} param1(entry)={entry:#x} "
          f"-> entry dc {entry - base:#x}")

    tgts, sites = call_targets(dc)
    in_blob = sum(1 for _, t, _ in sites if t < len(dc))
    print(f"call/jump sites: {len(sites)} ({sum(1 for s in sites if s[2])} calls); "
          f"targets in [0,len): {in_blob}/{len(sites)}; "
          f"distinct targets: {len(tgts)}")
    pro = dis(int.from_bytes(dc[entry - base:entry - base + 4], "big"),
              entry - base)
    pro2 = dis(int.from_bytes(dc[entry - base + 4:entry - base + 8], "big"),
               entry - base + 4)
    print(f"entry prologue: {pro} / {pro2}")

    pairs = pairs_scan(dc)
    in_range = [v for _, v in pairs if base <= v < base + len(dc)]
    print(f"pairs: {len(pairs)}; -> [base, base+len): {len(in_range)} "
          f"({100.0 * len(in_range) / len(pairs):.1f}%)")
    strs = set(m.start() for m in re.finditer(rb"[ -~]{5,}", dc))
    exact = [v for _, v in pairs if v - base in strs]
    print(f"pairs -> exact string start: {len(exact)} "
          f"({100.0 * len(exact) / len(pairs):.1f}%)")
    hi = collections.Counter(v >> 16 for v in in_range)
    print("hi16 histogram (top 10):",
          [(hex(h), c) for h, c in hi.most_common(10)])

    printable = [sum(32 <= b <= 126 for b in dc[i:i + BLOCK])
                 for i in range(0, len(dc), BLOCK)]
    pool_blocks = {i for i, p in enumerate(printable) if p >= BLOCK // 2}
    ptr_words = collections.Counter()
    for i in sorted(pool_blocks):
        chunk = dc[i * BLOCK:(i + 1) * BLOCK]
        for o in range(0, len(chunk) - 3, 4):
            v = int.from_bytes(chunk[o:o + 4], "big")
            if base <= v < base + len(dc):
                ptr_words[v - base] += 1
    at_tgt = sum(c for d, c in ptr_words.items() if d in tgts)
    print(f"rt-pointer words in data pools: {len(ptr_words)} distinct; "
          f"targets that are call/jump targets: {at_tgt}")
    print(f"FORMULA: rt = dc + {base:#x}")


if __name__ == "__main__":
    main()
