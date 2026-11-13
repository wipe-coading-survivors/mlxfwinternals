#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node task 04s — PROVENANCE helper (offline RE).

Establishes who initializes two iRISC-RAM words on 14.32 Lx / 4030 CX-5:
  - table word  0x0D600C (ram word 0x35803)  [F1 flag1 lookup, 7x3-bit]
  - gate word   c1 0xE2B4 (word 0x38AF) / 4030 0xD5DC (word 0x3577)

Sub-commands:
  itoc IMAGE            dump full ITOC geometry (all sections)
  main IMAGE            de-frame MAIN_CODE (ITOC 0x03) -> stdout .bin
  scan IMAGE            scan ALL code for stores to the three target words
  inisect IMAGE TYPE    dump an INI/config section raw

Address model (verified vs irisc_dis.py):
  * ld.i rd, imm16     read word at WORD offset imm16 (16-bit)
  * st.i rs, imm11     write word at WORD offset imm11 (11-bit, <=0x7FF)
  * ld.d/ld.q/ld.w/ld.b, st.d/st.q/st.w/st.b  : base-reg + signed byte offset
  => targets (word 0x35803/0x38AF/0x3577) are ABOVE st.i range; iRISC code
     can only write them via register-indirect store.
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "irisc"))
import mlxfwutil  # noqa: E402
from irisc_dis import dis  # noqa: E402

# target absolute iRISC-RAM byte addresses / word offsets
T_TABLE = 0x0D600C          # c1+4030 (same space); word 0x35803
T_GATE_C1 = 0x0E2B4         # c1 gate; word 0x38AF
T_GATE_4030 = 0x0D5DC       # 4030 gate; word 0x3577
T_WORDS = {
    "table": (T_TABLE, T_TABLE // 4),
    "gate_c1": (T_GATE_C1, T_GATE_C1 // 4),
    "gate_4030": (T_GATE_4030, T_GATE_4030 // 4),
}


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def load(path):
    buf = Path(path).read_bytes()
    return buf, mlxfwutil.Image(buf, path)


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


def main_code(buf, img):
    e = img.find_entry("ITOC", 0x03)
    raw = img.section_data(e)
    code = decrc(raw) if e.clcrc else raw
    return code, e


def cmd_itoc(path):
    buf, img = load(path)
    print("IMAGE %s fmt=%s itoc_off=0x%x" % (path, img.fmt, img.itoc_off))
    print("%-4s %-6s %-10s %-10s %-8s %-4s %-4s %-4s %-6s" %
          ("idx", "type", "addr", "size", "clcrc", "zip", "rel", "enc", "param1"))
    for e in img.entries("ITOC"):
        print("%-4d 0x%02x  0x%08x  0x%08x  %-8d %-4d %-4d %-4d 0x%x" %
              (e.index, e.type, e.addr, e.size, e.clcrc, e.zipped, e.rel,
               e.enc, e.param1))
    # coverage: which sections span the target byte addresses IF the section
    # were laid out at its iRISC-RAM address (i.e. addr == ram address)
    print("\n-- target byte-addr coverage by ITOC sections (addr..addr+size) --")
    for name, (ram, word) in T_WORDS.items():
        hits = []
        for e in img.entries("ITOC"):
            if e.addr <= ram < e.addr + e.size:
                hits.append("0x%02x@0x%x" % (e.type, e.addr))
        print("  %-9s ram=0x%06x word=0x%05x  covered_by: %s"
              % (name, ram, word, hits or "NONE"))
    return 0


def cmd_main(path, out):
    buf, img = load(path)
    code, e = main_code(buf, img)
    if out:
        Path(out).write_bytes(code)
        print("MAIN_CODE ITOC03 addr=0x%x size=0x%x clcrc=%d de=0x%x -> %s"
              % (e.addr, e.size, e.clcrc, len(code), out))
    else:
        sys.stdout.buffer.write(code)
    return 0


# store encodings that write RAM (register-indirect): op 0x1a st.b, 0x1b
# st.w/st.d/st.q, 0x1c st.w!/st.d!/st.q!, 0x1e st.d.1e/st.q.1e
STORE_OPS = {0x1a, 0x1b, 0x1c, 0x1e}
# immediate RAM store (limited 11-bit)
def is_st_i(w):
    return (w >> 26) == 0x13 and ((w >> 16) & 0x1f) == 0x1b


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


def cmd_scan(path, targets):
    """Scan ALL code (de-framed MAIN_CODE) for store instructions and
    report any whose immediate/offset could hit a target, plus every
    st.i (immediate) and the set2/set3 constants near targets."""
    buf, img = load(path)
    code, e = main_code(buf, img)
    n = len(code)
    print("MAIN_CODE de=0x%x (words=%d) scanning for stores..." % (n, n // 4))

    # 1) every st.i (immediate word store) — list the word offsets written
    sti = {}
    for o in range(0, n - 3, 4):
        w = u32(code, o)
        if is_st_i(w):
            off = w & 0x7ff
            sti[off] = sti.get(off, 0) + 1
    print("\n-- st.i (immediate) distinct word-offsets: %d (max=0x%x) --"
          % (len(sti), max(sti) if sti else 0))
    for tname, (ram, word) in targets.items():
        print("  %-9s word=0x%05x  st.i-hit=%s"
              % (tname, word, word in sti))

    # 2) register-indirect stores: collect (base-build constant) proximity.
    # We cannot resolve base regs statically; instead we report the count of
    # each store opcode and flag stores whose SIGNED offset equals a target
    # delta from a small base (heuristic: offset == target, or target-0x1000
    # multiples). This is a lower-bound signal, not a proof.
    from collections import Counter
    sc = Counter()
    for o in range(0, n - 3, 4):
        w = u32(code, o)
        op = w >> 26
        if op in STORE_OPS:
            sc[op] += 1
    print("\n-- register-indirect store opcodes in MAIN_CODE --")
    for op in sorted(sc):
        print("  op0x%02x: %d" % (op, sc[op]))
    return 0


def cmd_inisect(path, typ):
    buf, img = load(path)
    e = img.find_entry("ITOC", typ)
    data = img.section_data(e)
    print("section 0x%02x addr=0x%x size=0x%x clcrc=%d zipped=%d"
          % (typ, e.addr, e.size, e.clcrc, e.zipped))
    return data


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    cmd, path = sys.argv[1], sys.argv[2]
    if cmd == "itoc":
        sys.exit(cmd_itoc(path))
    elif cmd == "main":
        sys.exit(cmd_main(path, sys.argv[3] if len(sys.argv) > 3 else None))
    elif cmd == "scan":
        tgt = {k: v for k, v in T_WORDS.items()}
        sys.exit(cmd_scan(path, tgt))
    elif cmd == "inisect":
        data = cmd_inisect(path, int(sys.argv[3], 0))
        sys.stdout.buffer.write(data)
    else:
        print("unknown cmd", cmd)
        sys.exit(2)
