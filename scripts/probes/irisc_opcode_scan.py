#!/usr/bin/env python3
# Поиск iRISC-инструкций с 16-бит immediate из заданного набора (opcode-константы
# диспетчера PCIe-команд, напр. 0x930/0x931/0x932 flow-table family).
# Вход: de-clcrc-бинарник (код без line-CRC). BE32-слова, выравнивание 4.
# Спектр: iRISC.slaspec (определённые op с 16-бит imm в битах 0..15):
#   0x00 addi, 0x01 addi, 0x02 addi.hi, 0x03 addi.hi, 0x04 subi,
#   0x05 subsi, 0x06 set0, 0x07 set1, 0x08 set3, 0x09 set2,
#   0x0a and, 0x0b ands, 0x0c or, 0x0e xor, 0x12 ld.i (csrrsub=1),
#   0x17 ld.d.17/ld.q.17 (off14 в битах 2..15), 0x18 ld.b,
#   0x19 ld.q/ld.d (off14) / ld.w (off15 в битах 1..15).
# usage: python3 scripts/probes/irisc_opcode_scan.py <dc-bin> [0x930 0x931 0x932 ...]
import struct, sys

IMM16_OPS = {0x00: "addi", 0x01: "addi", 0x02: "addi.hi", 0x03: "addi.hi",
             0x04: "subi", 0x05: "subsi", 0x06: "set0", 0x07: "set1",
             0x08: "set3", 0x09: "set2", 0x0a: "and", 0x0b: "ands",
             0x0c: "or", 0x0e: "xor"}

def main():
    if len(sys.argv) < 2:
        print("usage: %s <dc-bin> [0xNNN ...]" % sys.argv[0]); return 2
    buf = open(sys.argv[1], "rb").read()
    targets = [int(t, 0) for t in sys.argv[2:]] or [0x930, 0x931, 0x932]
    n = len(buf) // 4
    words = struct.unpack_from(">%dI" % n, buf, 0)
    hits = {t: [] for t in targets}
    for i in range(n):
        w = words[i]
        imm16 = w & 0xFFFF
        op = w >> 26
        if imm16 in hits and op in IMM16_OPS:
            rd = (w >> 16) & 0x1F
            rs = (w >> 21) & 0x1F
            hits[imm16].append((i * 4, op, rd, rs))
        elif imm16 in hits and op == 0x12 and (w >> 25) & 1:
            rdlo = (w >> 16) & 0x1F
            hits[imm16].append((i * 4, 0x12, rdlo, 0))
        elif imm16 in hits and op in (0x17, 0x18, 0x19):
            off14 = (w >> 2) & 0x3FFF
            off15 = (w >> 1) & 0x7FFF
            off = off14 if op != 0x19 or (w & 3) == 2 else off15
            if off == imm16:
                rd = (w >> 16) & 0x1F
                hits[imm16].append((i * 4, op, rd, 0))
    for t in targets:
        hs = hits[t]
        print("== 0x%03x: %d hits" % (t, len(hs)))
        for off, op, rd, rs in hs:
            mn = "ld.i" if op == 0x12 else IMM16_OPS.get(op, "op%02x" % op)
            extra = " rd=%d" % rd if mn not in ("ld.d.17", "ld.b", "ld.q", "ld.d", "ld.w") else " rd=%d off14/15" % rd
            if mn in ("addi", "subi", "and", "ands", "or", "xor", "addi.hi", "subsi"):
                extra = " rd=r%d rs=r%d" % (rd, rs)
            if mn in ("set0", "set1", "set2", "set3"):
                extra = " rd=r%d rs=r%d" % (rd, rs)
            print("  %s @%#08x op=%#02x%s | imm16=0x%03x" % (mn, off, op, extra, t))
    # Кластеры: хиты разных opкодов в окне +-0x200
    allhits = []
    for t in targets:
        for off, op, rd, rs in hits[t]:
            allhits.append((off, t))
    allhits.sort()
    print("== clusters (all target hits within 0x200 of each other):")
    used = set()
    for a, ta in allhits:
        if a in used: continue
        cl = [(a, ta)]
        for b, tb in allhits:
            if b != a and b not in used and abs(b - a) <= 0x200:
                cl.append((b, tb))
        if len(cl) >= 2:
            for x in cl: used.add(x[0])
            kinds = sorted(set(t for _, t in cl))
            print("  cluster @%#x..%#x: %d hits %s" % (min(o for o, _ in cl),
                  max(o for o, _ in cl), len(cl), [hex(t) for t in kinds]))
            for o, t in sorted(cl):
                print("    %#x 0x%03x" % (o, t))
    return 0

if __name__ == "__main__":
    sys.exit(main())
