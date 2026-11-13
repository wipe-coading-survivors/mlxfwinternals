#!/usr/bin/env python3
"""task 04s — deep code scan of de-framed iRISC MAIN_CODE.

For each target iRISC-RAM word find:
  * ld.i readers (immediate word offset)
  * st.i writers (immediate, 11-bit only)
  * set2/set3 / addi.hi+addi constant builds of the address (and packed
    variants), with (dc, register)
  * register-indirect stores (st.d/st.q/st.w/st.b/...) whose base register
    was most recently set to a target constant (approx data-flow)
Scope = the ENTIRE de-framed MAIN_CODE (boot region + main), so the boot
code is not missed.
"""
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "irisc"))
from irisc_dis import dis  # noqa: E402


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


# target absolute byte addresses and the variants we expect in code
TARGETS = {
    "table":   [0x0D600C, 0x6B0060],   # direct + F1 packed (<<3)
    "gate_c1": [0x0E2BC, 0x0E2B4],     # g-fn ld.i*4  + stub
    "gate_4030": [0x0D5DC],
}
TVALS = set(v for vs in TARGETS.values() for v in vs)

STORE_OPS = {0x1a, 0x1b, 0x1c, 0x1e}


def storeoff(w, scale):
    hi = (w >> 16) & 0x1f
    if scale == 0:
        lo = w & 0x7ff
    elif scale == 1:
        lo = ((w >> 1) & 0x3ff) << 1
    else:
        lo = ((w >> 2) & 0x1ff) << 2
    v = (hi << 11) | lo
    return v - 0x10000 if v & 0x8000 else v


def main(code, label):
    n = len(code)
    words = n // 4
    print("### %s  words=%d (0x%x)" % (label, words, n))

    # ---- ld.i / st.i histograms ----
    ldi = Counter()
    sti = Counter()
    ldi_off = defaultdict(list)
    for o in range(0, words * 4, 4):
        w = u32(code, o)
        op = w >> 26
        if op == 0x12 and (w >> 25) & 1:
            imm = w & 0xffff
            ldi[imm] += 1
            ldi_off[imm].append(o)
        elif op == 0x13 and ((w >> 16) & 0x1f) == 0x1b:
            off = w & 0x7ff
            sti[off] += 1
    print("\n-- ld.i: %d distinct imm, total %d --" %
          (len(ldi), sum(ldi.values())))
    for name, vals in TARGETS.items():
        for v in vals:
            word = v // 4
            print("  %-9s byte=0x%06x word=0x%05x  ld.i-count=%d  st.i-count=%d"
                  % (name, v, word, ldi.get(word, 0), sti.get(word, 0)))
    print("  top ld.i imm (by count): " +
          ", ".join("0x%x:%d" % (i, c) for i, c in ldi.most_common(12)))
    print("  st.i: %d distinct, max=0x%x" %
          (len(sti), max(sti) if sti else 0))

    # ---- constant builds via set2+set3 (consecutive) and addi.hi+addi ----
    # irisc_dis field map: rd=(w>>16)&0x1f, rs=(w>>21)&0x1f, rt=(w>>11)&0x1f
    builds = defaultdict(list)   # const -> [(dc, reg)]
    for o in range(0, words * 4 - 4, 4):
        w0 = u32(code, o)
        w1 = u32(code, o + 4)
        # set2 rd,zero,hi ; set3 rd,rd,lo   (rs of set2 must be zero)
        if (w0 >> 26) == 0x09 and ((w0 >> 21) & 0x1f) == 0 and \
           (w1 >> 26) == 0x08 and ((w1 >> 21) & 0x1f) == ((w0 >> 16) & 0x1f):
            rd = (w0 >> 16) & 0x1f
            builds[((w0 & 0xffff) << 16) | (w1 & 0xffff)].append((o, rd))
        # addi.hi rd,zero,x ; addi rd,rd,y  (rs of addi.hi must be zero)
        if (w0 >> 26) == 0x03 and ((w0 >> 21) & 0x1f) == 0 and \
           (w1 >> 26) == 0x00 and ((w1 >> 21) & 0x1f) == ((w0 >> 16) & 0x1f):
            rd = (w0 >> 16) & 0x1f
            h = w0 & 0xffff
            if h & 0x8000:
                h -= 0x10000
            l = w1 & 0xffff
            if l & 0x8000:
                l -= 0x10000
            builds[(h << 16) | (l & 0xffff)].append((o, rd))

    print("\n-- target constant builds (set2+set3 / addi.hi+addi) --")
    for name, vals in TARGETS.items():
        for v in vals:
            hits = builds.get(v, [])
            print("  %-9s 0x%06x : %d build(s) %s"
                  % (name, v, len(hits),
                     ["dc0x%x r%d" % (dc, r) for dc, r in hits[:20]] or "-"))

    # ---- register-indirect stores whose base was set to a target const ----
    # track last set value per register (coarse: within 24 instr window)
    print("\n-- reg-indirect stores w/ base==target (24-instr window) --")
    found = 0
    for o in range(0, words * 4, 4):
        w = u32(code, o)
        op = w >> 26
        if op not in STORE_OPS:
            continue
        rs = (w >> 21) & 0x1f          # base register
        rt = (w >> 11) & 0x1f
        # find last build of rs in [o-24*4, o)
        base_val = None
        for o2 in range(max(0, o - 24 * 4), o, 4):
            w2 = u32(code, o2)
            if (w2 >> 26) == 0x08 and ((w2 >> 16) & 0x1f) == rs:
                # set3 rd,rd,lo  -> need the preceding set2 (rd==base, rs==zero)
                w3 = u32(code, o2 - 4) if o2 >= 4 else 0
                if (w3 >> 26) == 0x09 and ((w3 >> 21) & 0x1f) == 0 and \
                   ((w3 >> 16) & 0x1f) == rs:
                    base_val = ((w3 & 0xffff) << 16) | (w2 & 0xffff)
                    break
        if base_val in TVALS:
            # compute effective address = base_val + offset
            scale = 0 if op == 0x1a else (1 if (op in (0x1b, 0x1c) and w & 1) else 2)
            off = storeoff(w, scale)
            eff = base_val + off
            print("  STORE dc0x%06x  %s  base=0x%06x off=%+d eff=0x%06x  %s"
                  % (o, dis(w, o), base_val, off, eff & 0xffffffff,
                     "HIT-TARGET" if eff in TVALS else ""))
            found += 1
    if not found:
        print("  (none)")
    return 0


if __name__ == "__main__":
    path = sys.argv[1]
    code = Path(path).read_bytes()
    sys.exit(main(code, path))
