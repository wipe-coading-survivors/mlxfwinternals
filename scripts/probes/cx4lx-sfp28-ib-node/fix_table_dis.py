#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node task-04t — disassembly helper for the fix-table build.

De-frames MAIN_CODE (ITOC 0x03, clcrc 68B lines) of an image and disassembles
a dc range. Used for: (a) verify-before-fix (stock boot chain / injection site
/ cave), (b) SELF-CHECK of the BUILT image (patched site + stub verbatim).

Usage: fix_table_dis.py IMAGE [DC_LO DC_HI]   (dc in hex, dc = line*64+within)
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "irisc"))
import mlxfwutil  # noqa: E402
from irisc_dis import dis  # noqa: E402

SEC_ADDR = 0x16d000


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def dc_to_raw(dc):
    line, within = divmod(dc, 64)
    return SEC_ADDR + line * 68 + within


def main():
    path = sys.argv[1]
    lo = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x7edc
    hi = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x7f00
    buf = Path(path).read_bytes()
    img = mlxfwutil.Image(buf, path)
    e = img.find_entry("ITOC", 0x03)
    raw = img.section_data(e)
    code = decrc(raw) if e.clcrc else raw
    print("IMAGE %s MAIN_CODE ITOC03 addr=0x%x size=0x%x clcrc=%d de=0x%x"
          % (path, e.addr, e.size, e.clcrc, len(code)))
    for off in range(lo, min(hi, len(code)), 4):
        w = u32(code, off)
        print("%08x  %08x  %s" % (off, w, dis(w, off)))
    # cave zero-check (default dc 0x31cba0..0x31cc00) if in range
    if lo <= 0x31cba0 < hi or (lo > 0x31cba0 and hi > 0x31cba0):
        nz = [off for off in range(0x31cba0, 0x31cc00, 4)
              if off < len(code) and u32(code, off) != 0]
        print("CAVE 0x31cba0..0x31cc00 nonzero words: %s"
              % (nz[:16] if nz else "NONE (all-zero)"))


if __name__ == "__main__":
    main()
