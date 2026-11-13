#!/usr/bin/env python3
"""0x0C slot-signature scanner over raw firmware images (rate-knob task 4).

Scans every 16B-aligned slot of an image for the PCIE_PHY_UC_CODE
record signature: 6x0x00 prefix + BE16 op in a canon family
(hi(op) 0x50-0x5f read, 0x60-0x7f write; exact 0x4000 delay / 0x2000
cond / 0x8520 sync / 0x0000 nop -- journal
2026-10-24-pcie-phy-uc-format-re.md, op families as in phyuc_diff.py).
Reports slot-like counts, maximal non-nop runs and optional window
densities; used to probe images the ITOC tooling cannot parse
(calibration: CX-5 16.35 window 0x437200+0x1e80 -> 488/488 slot-likes;
CX-6Dx 22.50 window 0x696380+0x13260 -> 4462/4902; CX-7 28.50 signed
distributions -> 0 slot-likes, journal 2026-10-24-pcie-phy-rate-knob-
task-04.md §2).

Usage:
  scan_0c.py IMAGE [IMAGE ...] [--window 0xADDR:0xSIZE] ...
The headline "slot-likes" is the non-nop count ("nop separately", as in
the task-04 journal); nop-likes from zero padding are noted separately
so they never inflate it. Exit: 0 scan completed (any result, incl. 0
slot-likes), 2 usage error.
"""
import argparse
import struct
import sys
from collections import namedtuple
from pathlib import Path

SLOT = 16

SCAN_SLOT = struct.Struct(">5H")  # op, a, b, c, d at slot offset +6

ScanResult = namedtuple("ScanResult", "slot_likes non_nop runs")


def op_class(op):
    hi = op >> 8
    if 0x50 <= hi <= 0x5F:
        return "rd"
    if 0x60 <= hi <= 0x7F:
        return "wr"
    if op == 0x4000:
        return "delay"
    if op == 0x2000:
        return "cond"
    if op == 0x8520:
        return "sync"
    if op == 0x0000:
        return "nop"
    return None


def scan(blob):
    """Slot-likes (incl. nop) at 16B-aligned offsets + maximal non-nop
    runs as (start, length) pairs."""
    likes = 0
    non_nop = 0
    runs = []
    run_start = None
    run_len = 0
    for off in range(0, len(blob) - SLOT + 1, SLOT):
        if blob[off:off + 6] != b"\x00" * 6:
            cls = None
        else:
            op = SCAN_SLOT.unpack_from(blob, off + 6)[0]
            cls = op_class(op)
        if cls is None:
            if run_len:
                runs.append((run_start, run_len))
                run_start, run_len = None, 0
            continue
        likes += 1
        if cls == "nop":
            if run_len:
                runs.append((run_start, run_len))
                run_start, run_len = None, 0
            continue
        non_nop += 1
        if run_start is None:
            run_start, run_len = off, 1
        else:
            run_len += 1
    if run_len:
        runs.append((run_start, run_len))
    return ScanResult(likes, non_nop, runs)


def density(blob, addr, size):
    """(slot-likes, total slots, non-nop) among the 16B slots of
    [addr, addr+size)."""
    likes = total = non_nop = 0
    for off in range(addr, min(addr + size, len(blob) - SLOT + 1), SLOT):
        total += 1
        if blob[off:off + 6] != b"\x00" * 6:
            continue
        cls = op_class(SCAN_SLOT.unpack_from(blob, off + 6)[0])
        if cls is None:
            continue
        likes += 1
        if cls != "nop":
            non_nop += 1
    return likes, total, non_nop


def parse_window(spec):
    try:
        addr_s, size_s = spec.split(":")
        addr, size = int(addr_s, 16), int(size_s, 16)
    except ValueError:
        return None
    if addr < 0 or size <= 0 or addr % SLOT or size % SLOT:
        return None
    return addr, size


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="0x0C slot-signature scanner (rate-knob task 4)")
    ap.add_argument("images", nargs="+", help="raw firmware images")
    ap.add_argument("--window", action="append", default=[],
                    metavar="0xADDR:0xSIZE",
                    help="report slot density for a 16B-aligned window "
                         "(repeatable)")
    args = ap.parse_args(argv)

    windows = []
    for spec in args.window:
        w = parse_window(spec)
        if w is None:
            print(f"bad --window {spec!r}: need 0xADDR:0xSIZE, "
                  "both 16B-aligned", file=sys.stderr)
            return 2
        windows.append(w)

    for name in args.images:
        blob = Path(name).read_bytes()
        res = scan(blob)
        runs2 = [(s, n) for s, n in res.runs if n >= 2]
        print(f"{name}: {len(blob)} bytes; "
              f"slot-likes: {res.non_nop} "
              f"(+{res.slot_likes - res.non_nop} nop); "
              f"runs>=2: {len(runs2)}")
        for start, length in runs2:
            print(f"  run {start:#x} len {length}")
        for addr, size in windows:
            likes, total, non_nop = density(blob, addr, size)
            print(f"window {addr:#x}+{size:#x}: {likes}/{total} "
                  f"slot-likes ({non_nop} non-nop)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
