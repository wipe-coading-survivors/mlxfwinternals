#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node task 04v-B — offline RE helpers for the 4030 CX-5
(16.35.4030, FS4) images: de-frame ITOC sections (clcrc 68B lines), disassemble
dc ranges, dump ITOC geometry with RAM load addresses (param0).

Usage:
  re4030.py itoc IMAGE                     full ITOC + RAM-coverage of targets
  re4030.py deframe IMAGE TYPE OUT         de-frame section -> file
  re4030.py dis IMAGE TYPE [LO HI]         disassemble a dc range
  re4030.py words IMAGE TYPE OFFS...       print raw words at dc offsets

dc = offset in the de-framed section (dc = line*64 + within; raw =
sec_addr + line*68 + within). RAM load address of a section = ITOC param0
(verified: c1 MAIN_CODE param0=0x800000 matches the live-PC mapping
live-PC = dc + 0x800000 from docs/250-re/120-irisc/030-cx4lx-detour.md).
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "irisc"))
import mlxfwutil  # noqa: E402
from irisc_dis import dis  # noqa: E402

# absolute iRISC-RAM byte addresses under investigation
T_TABLE = 0x0D600C
T_GATE_4030 = 0x0D5DC


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


def sect(buf, img, typ):
    e = img.find_entry("ITOC", typ)
    raw = img.section_data(e)
    code = decrc(raw) if e.clcrc else raw
    return code, e


def cmd_itoc(path):
    buf = Path(path).read_bytes()
    img = mlxfwutil.Image(buf, path)
    print("IMAGE %s fmt=%s itoc_off=0x%x" % (path, img.fmt, img.itoc_off))
    ram_regions = []
    for e in img.entries("ITOC"):
        if e.param0:
            de = (e.size // 64 * 64) if e.clcrc else e.size
            ram_regions.append((e.param0, e.param0 + de, e.type, e.clcrc))
            print("  idx=%2d 0x%02x %-16s flash=0x%07x size=0x%07x clcrc=%d ram=0x%07x..0x%07x"
                  % (e.index, e.type, mlxfwutil.SECT_NAMES.get(e.type, '?'),
                     e.addr, e.size, e.clcrc, e.param0, e.param0 + de))
        else:
            print("  idx=%2d 0x%02x %-16s flash=0x%07x size=0x%07x clcrc=%d ram=-(no load addr)"
                  % (e.index, e.type, mlxfwutil.SECT_NAMES.get(e.type, '?'),
                     e.addr, e.size, e.clcrc))
    print("\n-- iRISC-RAM coverage of targets (by RAM load addr) --")
    for name, ram in (("table", T_TABLE), ("gate_4030", T_GATE_4030)):
        hits = ["0x%02x@ram0x%x" % (t, a) for a, b, t, _ in ram_regions if a <= ram < b]
        print("  %-9s ram=0x%06x  covered_by: %s" % (name, ram, hits or "NONE"))
    return 0


def cmd_deframe(path, typ, out):
    buf = Path(path).read_bytes()
    img = mlxfwutil.Image(buf, path)
    code, e = sect(buf, img, typ)
    Path(out).write_bytes(code)
    print("0x%02x %s flash=0x%x size=0x%x clcrc=%d de=0x%x ram=0x%x -> %s"
          % (typ, mlxfwutil.SECT_NAMES.get(typ, '?'), e.addr, e.size, e.clcrc,
             len(code), e.param0, out))
    return 0


def cmd_dis(path, typ, lo, hi):
    buf = Path(path).read_bytes()
    img = mlxfwutil.Image(buf, path)
    code, e = sect(buf, img, typ)
    print("0x%02x %s flash=0x%x size=0x%x clcrc=%d de=0x%x ram=0x%x"
          % (typ, mlxfwutil.SECT_NAMES.get(typ, '?'), e.addr, e.size, e.clcrc,
             len(code), e.param0))
    for off in range(lo, min(hi, len(code)), 4):
        w = u32(code, off)
        print("%08x  %08x  %s" % (off, w, dis(w, off)))
    return 0


def cmd_words(path, typ, offs):
    buf = Path(path).read_bytes()
    img = mlxfwutil.Image(buf, path)
    code, e = sect(buf, img, typ)
    for off in offs:
        if off + 4 <= len(code):
            print("dc 0x%06x = %08x  (%s)" % (off, u32(code, off), dis(u32(code, off), off)))
        else:
            print("dc 0x%06x OUT OF RANGE (de=0x%x)" % (off, len(code)))
    return 0


# task 04v-B provenance targets (absolute iRISC-RAM byte addresses;
# byte-verified from 4030 F1/g-fn disasm, see journal Step B/C)
T4030 = {
    "table_flag1_0D600C": 0x0D600C,
    "table_flag1_pack_6B0060": 0x6B0060,
    "table_flag0_0D6008": 0x0D6008,
    "table_flag0_pack_6B0040": 0x6B0040,
    "table_0D6010": 0x0D6010,
    "table_0D6014": 0x0D6014,
    "table_0D6018": 0x0D6018,
    "gate_4030_0D5DC": 0x0D5DC,
}
CODE_SECTS = [0x05, 0x03, 0x04, 0x06, 0x02, 0x07, 0x0a, 0x0c, 0x18]
SIGN_SECTS = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4}
STORE_OPS = {0x1a, 0x1b, 0x1c, 0x1e}


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


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


def scan_code(code):
    """04s all-sects pattern: ld.i/st.i per target word, constant builds
    (set2/set3 and addi/addi.hi pairs), reg-indirect stores with base
    built (24-instr window) to a target byte address."""
    from collections import Counter, defaultdict
    words = len(code) // 4
    ldi = Counter()
    sti = Counter()
    for o in range(0, words * 4, 4):
        w = u32(code, o)
        op = w >> 26
        if op == 0x12 and (w >> 25) & 1:
            ldi[w & 0xffff] += 1
        elif op == 0x13 and ((w >> 16) & 0x1f) == 0x1b:
            sti[w & 0x7ff] += 1
    builds = defaultdict(list)
    prev_addi = None
    for o in range(0, words * 4, 4):
        w = u32(code, o)
        op = w >> 26
        if op == 0x09 and ((w >> 21) & 0x1f) == 0:
            w1 = u32(code, o + 4) if o + 4 < len(code) else 0
            if (w1 >> 26) == 0x08 and ((w1 >> 21) & 0x1f) == ((w >> 16) & 0x1f):
                builds[((w & 0xffff) << 16) | (w1 & 0xffff)].append(
                    (o, (w >> 16) & 0x1f, "set2/set3"))
        if op in (0x00, 0x01):
            prev_addi = (o, (w >> 16) & 0x1f, s16(w & 0xffff))
        elif op in (0x02, 0x03) and prev_addi is not None:
            po, prd, pimm = prev_addi
            if po + 4 == o and prd == (w >> 16) & 0x1f:
                val = (pimm + ((w & 0xffff) << 16)) & 0xffffffff
                builds[val].append((o, prd, "addi/addi.hi"))
        prev_addi = None if op not in (0x00, 0x01) else prev_addi
    def base_built_at(o2, rs):
        w2 = u32(code, o2)
        op2 = w2 >> 26
        if op2 == 0x08 and ((w2 >> 16) & 0x1f) == rs:
            if o2 >= 4:
                w3 = u32(code, o2 - 4)
                if (w3 >> 26) == 0x09 and ((w3 >> 21) & 0x1f) == 0 and \
                   ((w3 >> 16) & 0x1f) == rs:
                    return ((w3 & 0xffff) << 16) | (w2 & 0xffff)
        elif op2 in (0x02, 0x03) and ((w2 >> 16) & 0x1f) == rs and \
             ((w2 >> 21) & 0x1f) == rs:
            if o2 >= 4:
                w3 = u32(code, o2 - 4)
                if (w3 >> 26) in (0x00, 0x01) and ((w3 >> 21) & 0x1f) == 0 and \
                   ((w3 >> 16) & 0x1f) == rs:
                    return (s16(w3 & 0xffff) + ((w2 & 0xffff) << 16)) & 0xffffffff
        return None

    tvals = set(T4030.values())
    stores = []
    for o in range(0, words * 4, 4):
        w = u32(code, o)
        op = w >> 26
        if op not in STORE_OPS:
            continue
        rs = (w >> 21) & 0x1f
        base_val = None
        for o2 in range(max(0, o - 24 * 4), o, 4):
            bv = base_built_at(o2, rs)
            if bv in tvals:
                base_val = bv
                break
        if base_val in tvals:
            scale = 0 if op == 0x1a else (1 if (op in (0x1b, 0x1c) and w & 1) else 2)
            eff = (base_val + storeoff(w, scale)) & 0xffffffff
            stores.append((o, base_val, eff, dis(w, o)))
    return ldi, sti, builds, stores


def cmd_scan(path):
    buf = Path(path).read_bytes()
    img = mlxfwutil.Image(buf, path)
    print("SCAN %s fmt=%s" % (path, img.fmt))
    for t in CODE_SECTS:
        try:
            e = img.find_entry("ITOC", t)
        except KeyError:
            continue
        code = decrc(img.section_data(e)) if e.clcrc else img.section_data(e)
        ldi, sti, builds, stores = scan_code(code)
        print("\n=== 0x%02x %s (flash 0x%x, clcrc=%d, de=0x%x, ram=0x%x) ==="
              % (t, mlxfwutil.SECT_NAMES.get(t, '?'), e.addr, e.clcrc,
                 len(code), e.param0))
        for k, v in T4030.items():
            word = v // 4
            b = builds.get(v, [])
            print("  %-24s word=0x%05x ld.i=%-3d st.i=%-3d builds=%s"
                  % (k, word, ldi.get(word, 0), sti.get(word, 0),
                     ["dc0x%x r%d %s" % x for x in b[:8]] or "-"))
        if stores:
            print("  REG-INDIRECT STORES to target base:")
            for o, bv, eff, d in stores:
                print("    dc0x%06x base=0x%06x eff=0x%06x %s" % (o, bv, eff, d))
        if sti:
            print("  st.i max word=0x%x (byte 0x%x)" % (max(sti), max(sti) * 4))
    return 0


def fields7(w):
    return [(w >> (3 * i)) & 7 for i in range(7)]


def cmd_data(path):
    buf = Path(path).read_bytes()
    img = mlxfwutil.Image(buf, path)
    print("DATA %s fmt=%s" % (path, img.fmt))
    for e in img.entries("ITOC"):
        if e.type in CODE_SECTS or e.type in SIGN_SECTS:
            continue
        data = img.section_data(e)
        n = len(data) // 4
        hit6 = []
        hit5014 = []
        tag_gate = []
        for o in range(0, n * 4, 4):
            w = u32(data, o)
            if 6 in fields7(w):
                hit6.append((o, w))
            if w == 0x5014:
                hit5014.append(o)
            if w == T4030["gate_4030_0D5DC"] or w == T4030["table_flag1_0D600C"]:
                tag_gate.append((o, w))
        line = ("  0x%02x %-16s @0x%07x size=0x%07x ram=0x%x: "
                "words7x3bit_with6=%d  word==0x5014=%d  addr-tags=%s"
                % (e.type, mlxfwutil.SECT_NAMES.get(e.type, '?'), e.addr,
                   e.size, e.param0, len(hit6), len(hit5014),
                   ["off0x%x=%08x" % x for x in tag_gate[:4]] or "-"))
        print(line)
        for o, w in hit6[:3]:
            print("      e.g. off 0x%05x = %08x fields=%s" % (o, w, fields7(w)))
    e = img.find_entry("ITOC", 0x30)
    raw = img.section_data(e)
    if raw[:2] == b"\x78\xda":
        import zlib
        ini = zlib.decompress(raw).decode("latin1")
        lines = ini.split("\n")
        print("\nINI 0x30 @0x%x size=0x%x: zlib %d bytes, %d lines"
              % (e.addr, e.size, len(ini), len(lines)))
        kw = ("an_", "an-", "cable", "class", "gate", "sfp", "qsfp", "module",
              "link_type", "ib", "eth", "speed", "vpi", "aneg", "autoneg")
        hits = [(i, l) for i, l in enumerate(lines)
                if any(k in l.lower() for k in kw)]
        print("  keyword hits (%d):" % len(hits))
        for i, l in hits[:40]:
            print("    %4d %s" % (i, l))
    else:
        print("\nINI 0x30 @0x%x: NOT zlib (starts %02x %02x)" % (e.addr, raw[0], raw[1]))
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    cmd, path = sys.argv[1], sys.argv[2]
    if cmd == "itoc":
        sys.exit(cmd_itoc(path))
    elif cmd == "deframe":
        sys.exit(cmd_deframe(path, int(sys.argv[3], 0), sys.argv[4]))
    elif cmd == "dis":
        lo = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0
        hi = int(sys.argv[5], 0) if len(sys.argv) > 5 else lo + 0x100
        sys.exit(cmd_dis(path, int(sys.argv[3], 0), lo, hi))
    elif cmd == "words":
        sys.exit(cmd_words(path, int(sys.argv[3], 0),
                           [int(x, 0) for x in sys.argv[4:]]))
    elif cmd == "scan":
        sys.exit(cmd_scan(path))
    elif cmd == "data":
        sys.exit(cmd_data(path))
    else:
        print("unknown cmd", cmd)
        sys.exit(2)
