#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node task-1b — F1 xref scanner.

De-frames MAIN_CODE (ITOC 0x03, clcrc 68B lines) of an image and finds all
PC-relative call/jump sites targeting the F1 lookup entry (dc 0x18c05c).
Self-contained re-implementation of the 04x scanner logic
(/tmp/opencode/04x-xref-scan.py — that file is NOT in the repo and must not
be a dependency); de-frame approach is identical to fix_table_dis.py.

Usage: f1-xref-scan.py IMAGE [TARGET_DC]   (dc in hex, default 0x18c05c)

A "site" is a de-framed word whose opcode class is 0x25 (call/jump):
    call: bit24 = 0,   jump: bit24 = 1
    target = dc_off + s24(word & 0xffffff) * 4
where s24 sign-extends the 24-bit PC-relative offset (scripts/irisc/enc.py:
jump/call; scripts/irisc/irisc_dis.py: op 0x25). A site "targets" T when
target == T. Output is one line per site: dc offset, kind, word, disasm.
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "irisc"))
import mlxfwutil  # noqa: E402
from irisc_dis import dis  # noqa: E402

F1_ENTRY = 0x18c05c


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


def s24(v):
    v &= 0xffffff
    return v - 0x1000000 if v & 0x800000 else v


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def deframe(path):
    buf = Path(path).read_bytes()
    img = mlxfwutil.Image(buf, path)
    e = img.find_entry("ITOC", 0x03)
    raw = img.section_data(e)
    code = decrc(raw) if e.clcrc else raw
    return e, code


def scan(code, target):
    sites = []
    for boff in range(0, len(code) - 3, 4):
        w = u32(code, boff)
        if (w >> 26) != 0x25:
            continue
        tgt = boff + s24(w) * 4
        if tgt == target:
            kind = "jump" if (w >> 24) & 1 else "call"
            sites.append((boff, kind, w))
    return sites


def main():
    path = sys.argv[1]
    target = int(sys.argv[2], 0) if len(sys.argv) > 2 else F1_ENTRY
    e, code = deframe(path)
    print("IMAGE %s MAIN_CODE ITOC03 addr=0x%x size=0x%x clcrc=%d de=0x%x"
          % (path, e.addr, e.size, e.clcrc, len(code)))
    print("TARGET dc 0x%x%s" % (target, " (F1-lookup)" if target == F1_ENTRY else ""))
    sites = scan(code, target)
    print("SITES %d" % len(sites))
    for off, kind, w in sites:
        print("   0x%08x %-4s %08x  %s" % (off, kind, w, dis(w, off)))
    return 0 if sites else 1


if __name__ == "__main__":
    sys.exit(main())
