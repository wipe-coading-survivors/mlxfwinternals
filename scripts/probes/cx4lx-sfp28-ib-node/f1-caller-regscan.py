#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node task-1c — F1 caller register scan (r11/r12 clobber audit).

For every F1 call site (target dc 0x18c05c) found by the T1b scanner's
deframe+scan (imported from the sibling f1-xref-scan.py, same directory —
importlib pattern per scripts/s1/dump.py), identifies the containing
function:
    start = nearest PRECEDING prologue pair 480300bc (csr.r r3,csr0xbc) +
            6c201806 (st.d r3,r1,0x4) — the stock F1-ABI prologue pattern;
    end   = next prologue pair after start, or start + 0x4000 (cap).
Disassembles the body range and reports r11/r12 register mentions per
function (regex rN over irisc_dis output; a mention = read or write, i.e.
the conservative "any use" measure).

Purpose: clobber audit of the 04y trampoline stub's save registers
(r11=link, r12=flag, r10=key — r10 is inside the F1 net-clobber set {r4..r10}
and needs no scan). The safety metric is "r11/r12 not LIVE across the F1
call" (per-function W/R timeline — task-1c journal Step 3.2: 0/12 straddles);
this script reports the CONSERVATIVE "any mention" measure, whose 5/12-clean
verdict (7/12 functions use r11) is the EXPECTED outcome on the stock image,
not a failure. The stub itself never writes r17/r18 (the T1c defect: fn
0x1f5bac keeps r17/r18 live across F1 calls, so the old r17/r18 scratch
design was unsafe).

Usage: f1-caller-regscan.py IMAGE [TARGET_DC]   (dc in hex, default 0x18c05c)

Exit 0 iff every F1-caller function has 0 r11 AND 0 r12 mentions.
"""
import importlib.util
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "irisc"))
from irisc_dis import dis  # noqa: E402

# Reuse the T1b scanner's deframe+scan (single source of truth for sites):
_spec = importlib.util.spec_from_file_location("f1_xref_scan", HERE / "f1-xref-scan.py")
f1x = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(f1x)
deframe = f1x.deframe
scan = f1x.scan

F1_ENTRY = 0x18c05c
PROLOGUE = (0x480300bc, 0x6c201806)  # csr.r r3,csr0xbc ; st.d r3,r1,0x4
FN_CAP = 0x4000                      # body cap, bytes
WATCH = (11, 12)                     # r11 (link save), r12 (flag save)
RW = re.compile(r'\b(r\d+)\b')


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def prologue_starts(code):
    out = []
    for off in range(0, len(code) - 7, 4):
        if u32(code, off) == PROLOGUE[0] and u32(code, off + 4) == PROLOGUE[1]:
            out.append(off)
    return out


def main():
    path = sys.argv[1]
    target = int(sys.argv[2], 0) if len(sys.argv) > 2 else F1_ENTRY
    e, code = deframe(path)
    print("IMAGE %s MAIN_CODE ITOC03 addr=0x%x size=0x%x clcrc=%d de=0x%x"
          % (path, e.addr, e.size, e.clcrc, len(code)))
    print("TARGET dc 0x%x%s" % (target, " (F1-lookup)" if target == F1_ENTRY else ""))
    sites = scan(code, target)
    print("SITES %d" % len(sites))
    if not sites:
        print("FATAL: no F1 sites found (image changed?)")
        return 2
    prologues = prologue_starts(code)
    print("PROLOGUE PAIR 480300bc+6c201806: %d found" % len(prologues))

    fns = {}
    unassigned = []
    for off, kind, w in sites:
        start, end = None, None
        prev = None
        for p in prologues:
            if p <= off:
                prev = p
            else:
                end = p
                break
        if prev is None:
            unassigned.append(off)
            continue
        start = prev
        end = min(end if end is not None else len(code), start + FN_CAP)
        fn = fns.setdefault(start, {"sites": [], "end": end})
        fn["sites"].append((off, kind, w))

    if unassigned:
        print("FATAL: sites with no preceding prologue: %s"
              % ["0x%x" % o for o in unassigned])
        return 2

    print("F1-CALLER FUNCTIONS %d" % len(fns))
    bad = 0
    for start in sorted(fns):
        fn = fns[start]
        end = fn["end"]
        n11 = n12 = 0
        first = {11: None, 12: None}
        for off in range(start, end, 4):
            d = dis(u32(code, off), off)
            regs = {int(m[1:]) for m in RW.findall(d)}
            for r in WATCH:
                if r in regs:
                    if r == 11:
                        n11 += 1
                        first[11] = first[11] or (off, d)
                    else:
                        n12 += 1
                        first[12] = first[12] or (off, d)
        sites_s = ", ".join("0x%x" % o for o, _, _ in fn["sites"])
        flag = "" if (n11 == 0 and n12 == 0) else "  <-- USE FOUND"
        if n11 or n12:
            bad += 1
        print("FN 0x%06x sites=%2d body 0x%06x..0x%06x r11=%d r12=%d%s"
              % (start, len(fn["sites"]), start, end, n11, n12, flag))
        print("     sites: %s" % sites_s)
        for r in WATCH:
            if first[r]:
                off, d = first[r]
                print("     first r%d @ 0x%06x: %s" % (r, off, d))
    ok = bad == 0
    print("VERDICT: r11/r12 unused in %d/%d F1-caller functions"
          % (len(fns) - bad, len(fns)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
