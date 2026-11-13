#!/usr/bin/env python3
"""task 04s — extract all ITOC code sections (de-framing clcrc) and scan each
for stores/reads/builds of the target iRISC-RAM words. Covers boot (ROM_CODE)
and every other code section, not just MAIN_CODE."""
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "irisc"))
import mlxfwutil  # noqa: E402
from irisc_dis import dis  # noqa: E402

CODE_SECTS = [0x05, 0x02, 0x03, 0x04, 0x06, 0x07, 0x0a, 0x0c, 0x18]

# targets: absolute byte addr -> word offset
TARGETS = {
    "table_0D600C": 0x0D600C,
    "table_packed_6B0060": 0x6B0060,
    "gate_c1_0E2BC": 0x0E2BC,
    "gate_c1_0E2B4": 0x0E2B4,
    "gate_4030_0D5DC": 0x0D5DC,
}
TVALS = set(TARGETS.values())
TWORDS = {k: v // 4 for k, v in TARGETS.items()}
STORE_OPS = {0x1a, 0x1b, 0x1c, 0x1e}


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


def storeoff(w, scale):
    hi = (w >> 16) & 0x1f
    lo = (w & 0x7ff) if scale == 0 else (((w >> 1) & 0x3ff) << 1 if scale == 1
                                        else ((w >> 2) & 0x1ff) << 2)
    v = (hi << 11) | lo
    return v - 0x10000 if v & 0x8000 else v


def scan_code(code, label):
    n = len(code)
    words = n // 4
    ldi = Counter()
    sti = Counter()
    for o in range(0, words * 4, 4):
        w = u32(code, o)
        op = w >> 26
        if op == 0x12 and (w >> 25) & 1:
            ldi[w & 0xffff] += 1
        elif op == 0x13 and ((w >> 16) & 0x1f) == 0x1b:
            sti[w & 0x7ff] += 1
    # constant builds
    builds = defaultdict(list)
    for o in range(0, words * 4 - 4, 4):
        w0 = u32(code, o)
        w1 = u32(code, o + 4)
        if (w0 >> 26) == 0x09 and ((w0 >> 21) & 0x1f) == 0 and \
           (w1 >> 26) == 0x08 and ((w1 >> 21) & 0x1f) == ((w0 >> 16) & 0x1f):
            builds[((w0 & 0xffff) << 16) | (w1 & 0xffff)].append((o, (w0 >> 16) & 0x1f))
    # reg-indirect stores w/ base built to a target (24-instr window)
    stores = []
    for o in range(0, words * 4, 4):
        w = u32(code, o)
        op = w >> 26
        if op not in STORE_OPS:
            continue
        rs = (w >> 21) & 0x1f
        base_val = None
        for o2 in range(max(0, o - 24 * 4), o, 4):
            w2 = u32(code, o2)
            if (w2 >> 26) == 0x08 and ((w2 >> 16) & 0x1f) == rs:
                w3 = u32(code, o2 - 4) if o2 >= 4 else 0
                if (w3 >> 26) == 0x09 and ((w3 >> 21) & 0x1f) == 0 and \
                   ((w3 >> 16) & 0x1f) == rs:
                    base_val = ((w3 & 0xffff) << 16) | (w2 & 0xffff)
                    break
        if base_val in TVALS:
            scale = 0 if op == 0x1a else (1 if (op in (0x1b, 0x1c) and w & 1) else 2)
            eff = (base_val + storeoff(w, scale)) & 0xffffffff
            stores.append((o, base_val, eff, dis(w, o)))
    return ldi, sti, builds, stores


def main(path):
    buf = Path(path).read_bytes()
    img = mlxfwutil.Image(buf, path)
    print("IMAGE %s" % path)
    for t in CODE_SECTS:
        try:
            e = img.find_entry("ITOC", t)
        except KeyError:
            continue
        raw = img.section_data(e)
        code = decrc(raw) if e.clcrc else raw
        ldi, sti, builds, stores = scan_code(code, t)
        name = mlxfwutil.SECT_NAMES.get(t, hex(t))
        print("\n=== 0x%02x %s  (flash 0x%x, %d B, clcrc=%d, de=0x%x) ==="
              % (t, name, e.addr, len(raw), e.clcrc, len(code)))
        for k, v in TARGETS.items():
            word = v // 4
            b = builds.get(v, [])
            print("  %-20s word=0x%05x  ld.i=%-3d st.i=%-3d builds=%s"
                  % (k, word, ldi.get(word, 0), sti.get(word, 0),
                     ["dc0x%x r%d" % (dc, r) for dc, r in b[:8]] or "-"))
        if stores:
            print("  REG-INDIRECT STORES to target base:")
            for o, bv, eff, d in stores:
                print("    dc0x%06x base=0x%06x eff=0x%06x %s" % (o, bv, eff, d))
        if sti:
            print("  st.i max word=0x%x" % max(sti))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
