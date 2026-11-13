#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node — map FW assert runtime addresses to MAIN_CODE dc.

Offline RE helper for the C12-analog assert incident (FW 14.32.1900, MCX4121A
CX-4 Lx MT27710). Establishes the runtime link-base B of the de-framed
MAIN_CODE (ITOC 0x03) and translates assert_exit_ptr / assert_callra to dc,
then disassembles the assert site, the patched apply_stamping site, and finds
the call chain.

Established facts (see docs/superpowers/journal/2026-10-10-cx4lx-sfp28-ib-node-
assert-re.md):
  * iRISC words in flash are BIG-ENDIAN; de-framed MAIN_CODE (clcrc 68B lines)
    is 0x31cc00 B; dc == Ghidra address of the de-framed project (docs/250-re/120-irisc/005-endian-addressing.md).
  * Runtime base B = 0x800000. Independent in-image anchor: the trace string
    "inside apply_stamping_ib. local=%d,compliance_code_stamping_disable=%d"
    sits at dc 0x2df284 and its runtime address is documented as rt 0xadf284
    (cx4lx-an-fsm task-04) -> delta exactly 0x800000. docs/250-re/120-irisc/005-endian-addressing.md also states
    "assert addr = base 0x800000 + dc offset".
  * The human strings "firmware internal error" / "irisc not responding" are
    DRIVER-side (mlx5_core print_health_info), NOT in the FW image.

Usage:
  re-assert-map.py IMAGE [--rt EXIT CALLRA ...] [--patch-dc 0x1f1f00]
Default assert addresses = incident assert #1 (exit 0x0098c120, callra
0x0098c0cc) and #2 (exit 0x00a0ad8c, callra 0x009c8778).
"""
import argparse
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "irisc"))
from irisc_dis import dis  # noqa: E402  (canonical BE decoder, docs/250-re/120-irisc/015-decoders.md)

B = 0x800000
ANCHOR_STR = b"inside apply_stamping_ib. local=%d,compliance_code_stamping_disable=%d"
ANCHOR_DC = 0x2df284      # where the string is in the de-framed code
ANCHOR_RT = 0xadf284      # documented runtime address (task-04 §4)


def decrc(data: bytes) -> bytes:
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


def main_section(buf: bytes):
    sys.path.insert(0, str(ROOT))
    import mlxfwutil  # noqa: E402
    im = mlxfwutil.Image(buf, "img")
    e = im.find_entry("ITOC", 0x03)
    raw = im.section_data(e)
    code = decrc(raw) if e.clcrc else raw
    return code, e


def u32(code, o):
    return struct.unpack_from(">I", code, o)[0]


def rt_to_dc(rt):
    return rt - B


def find_calls(code, target):
    out = []
    n = len(code)
    for o in range(0, n - 3, 4):
        w = u32(code, o)
        if (w >> 26) == 0x25 and not (w >> 24) & 1:
            tgt = o + ((w & 0xFFFFFF) - (0x1000000 if w & 0x800000 else 0)) * 4
            if tgt == target:
                out.append(o)
    return out


def disrange(code, lo, hi, label):
    print("\n===== %s  [%#x .. %#x) =====" % (label, lo, hi))
    for o in range(lo, hi, 4):
        w = u32(code, o)
        print("%08x  %08x  %s" % (o, w, dis(w, o)))


def nearest_string(code, off, back=0x800, fwd=0x40):
    lo, hi = max(0, off - back), min(len(code), off + fwd)
    hits = []
    for m in re.finditer(rb"[\x20-\x7e]{8,}", code[lo:hi]):
        s = m.start() + lo
        hits.append((s, code[s:s + 40].split(b"\x00")[0].decode("latin1")))
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image")
    ap.add_argument("--rt", nargs="+", default=[0x0098c120, 0x0098c0cc,
                                               0x00a0ad8c, 0x009c8778],
                    help="assert runtime addrs (exit/callra ...), base 0x800000")
    ap.add_argument("--patch-dc", type=lambda s: int(s, 0), default=0x1f1f00)
    a = ap.parse_args(argv)

    buf = Path(a.image).read_bytes()
    code, e = main_section(buf)
    print("MAIN_CODE ITOC03 addr=0x%x size=0x%x clcrc=%d de-framed=0x%x"
          % (e.addr, e.size, e.clcrc, len(code)))

    # B verification via in-image string anchor
    found = code.find(ANCHOR_STR)
    print("anchor string dc found=%s expected=0x%x -> B check rt-dc=0x%x (want 0x800000)"
          % (hex(found) if found >= 0 else "MISSING", ANCHOR_DC,
             (ANCHOR_RT - found) if found >= 0 else -1))
    print("patch site dc 0x%x word = %08x"
          % (a.patch_dc, u32(code, a.patch_dc)))

    print("\n=== assert runtime -> dc (B=0x800000) ===")
    dcs = []
    for rt in a.rt:
        dc = rt_to_dc(rt)
        dcs.append(dc)
        ok = 0 <= dc < len(code)
        print("  rt 0x%08x -> dc 0x%06x  in-range=%s" % (rt, dc, ok))

    # assert #1 region + apply_stamping region
    if dcs:
        a1 = dcs[0]
        disrange(code, a1 - 0x60, a1 + 0x60, "ASSERT #1 (exit dc 0x%x)" % a1)
        # locate the ext_synd set3 near the exit (set3 r4,zero,imm == ext_synd)
        for o in range(a1, min(len(code), a1 + 0x40), 4):
            w = u32(code, o)
            if (w >> 26) == 0x08:
                print("  [set3] @dc 0x%x imm=0x%x  (candidate ext_synd)" % (o, w & 0xFFFF))
    disrange(code, 0x1f1e04, 0x1f1f60, "apply_stamping (patch dc 0x%x) prologue+term" % a.patch_dc)

    # call chain: assert fn (enclosing the exit) and its callers
    print("\n=== call chain (call <dc> sites) ===")
    for name, tgt in [("assert-fn 0x18c05c", 0x18c05c),
                      ("caller-fn 0x18bf70", 0x18bf70)]:
        cs = find_calls(code, tgt)
        print("  %s: %d caller(s) %s" % (name, len(cs), [hex(c) for c in cs[:12]]))
    for c in find_calls(code, 0x18bf70):
        ns = nearest_string(code, c)
        print("    F0-caller 0x%06x nearby: %s" % (c, ns[:4] or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
