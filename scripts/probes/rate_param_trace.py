#!/usr/bin/env python3
"""Flash-source trace for PCIe per-speed parameters (rate-knob task 3).

Method (task brief steps 1-3; offline, inputs are section dumps made by
`mlxfwutil.py extract -s S --raw`):
  * pair diff of same-silicon Gen3<->Gen4 SKU sections: every differing
    byte is classified against the known config-field map (docs/750-exp/130-cx4lx-pcie-gen4 §3 +
    phase-A 2026-10-24 + task-02 0x08 diff); unclassified diffs are the
    NON-config speed-data candidates the brief searches for (exit 1);
  * rate scan of a section blob (GC-3): GT/s-scale {2500,5000,8000,
    16000} in BE/LE 16/32 and MHz-scale {25,50,80,100,125,160} BE16,
    each hit with context bytes; every hit needs an alternative-domain
    control before it may count as rate arithmetic;
  * window-slot geometry: decode a raw 32-bit window word into the 6-bit
    speed fields (speeds 1-3 packed >>{0,6,12} & 0x3f, speed-4 >>4,
    LX feature-gate bit 21 raw) -- the geometry a flash source would
    have to match to feed the slots verbatim (slots: LX RAM[0x3ad1]/
    [0x3ab9], CX-5 RAM[0x3771]/[0x3759], x4 regspace convention);
  * schedule-domain run reader (BE16 words in 0x600..0x8ff): the domain
    that must NOT be confused with per-speed data (task 2: schedule
    table is Gen-invariant, 0x08+0xf0 copy and the 0x11 copy).

Usage:
  rate_param_trace.py A.0x08.bin B.0x08.bin [--sect 0x08]
  rate_param_trace.py --rate-scan FILE [FILE ...]
  rate_param_trace.py --window 0x00010000
Section type is inferred from the `*.0xNN.bin` filename suffix when
--sect is absent. Exit: 0 ok, 1 unclassified (candidate) diff bytes,
2 usage error.
"""
import argparse
import re
import struct
import sys
from pathlib import Path

UNKNOWN = "UNKNOWN"

KNOWN_FIELDS = [
    # (sect, lo, hi, label) -- every offset that legitimately varies
    # between SKUs of one FW revision (canon docs/750-exp/130-cx4lx-pcie-gen4 §3, phase-A
    # 2026-10-24 config correlation, task-02/03 diffs)
    (0x08, 0x22, 0x22, "SKU-class byte (board/SKU structural)"),
    (0x08, 0x23, 0x23, "max_speed (bit-flags of supported speeds; Gen)"),
    (0x08, 0xA0, 0xA1, "SKU variant bytes (structural)"),
    (0x08, 0x128, 0x12B, "count-pair (0x64,N): N = 0x0C record count"),
    (0x09, 0x241, 0x37F, "port-map/label zone (SKU-structural)"),
    (0x09, 0x86C, 0x86F, "PHY tuning quartet (per-silicon+Gen)"),
    (0x11, 0x06, 0x0F, "build/rel stamp (metadata)"),
    (0x11, 0x2D, 0x2D, "device_id (identity; Gen badge Ex)"),
    (0x11, 0x3C, 0x3D, "subsystem id (identity)"),
    (0x11, 0x47, 0x47, "x16 Gen marker (bit-flags; x16 boards)"),
    (0x11, 0x93, 0x93, "cap_index (bit-flags; Gen)"),
    (0x11, 0x120, 0x127, "SKU/board-variant bytes (structural; never flip within same-product Gen pairs)"),
    (0x11, 0x135, 0x135, "identity variant byte"),
    (0x11, 0x1A8, 0x1A8, "SKU variant byte"),
    (0x11, 0x2B7, 0x2C0, "variant/identity bytes"),
]

GTS = {2500, 5000, 8000, 16000}
MHZ = {25, 50, 80, 100, 125, 160}

SECT_RE = re.compile(r"\.0x([0-9a-fA-F]{1,2})\.bin$")


def classify(sect: int, off: int) -> str:
    for s, lo, hi, label in KNOWN_FIELDS:
        if s == sect and lo <= off <= hi:
            return label
    return UNKNOWN


def diff_sections(a: bytes, b: bytes):
    n = min(len(a), len(b))
    return [(i, a[i], b[i]) for i in range(n) if a[i] != b[i]]


def rate_scan(blob: bytes):
    """(off, align, value, tag, ctx_hex) for rate-scale values; every
    hit is a candidate that still owes a GC-3 alternative control."""
    hits = []
    for off in range(len(blob) - 1):
        for fmt, sz, nm in ((">H", 2, "BE16"), ("<H", 2, "LE16"),
                            (">I", 4, "BE32"), ("<I", 4, "LE32")):
            if off + sz > len(blob):
                continue
            v = struct.unpack_from(fmt, blob, off)[0]
            tag = None
            if v in GTS:
                tag = f"{v}GT/s"
            elif v in MHZ and nm == "BE16":
                tag = f"{v}MHz"
            if tag:
                ctx = blob[max(0, off - 4):off + sz + 4].hex()
                hits.append((off, nm, v, tag, ctx))
    return hits


def window_fields(word: int, slot: str):
    """6-bit speed fields per the disasm canon (mask 0x3f):
    speeds123 -> (speed1, speed2, speed3) at shifts 0/6/12;
    speed-4 -> shift 4 of its own word."""
    if slot == "speeds123":
        return ((word >> 0) & 0x3F, (word >> 6) & 0x3F, (word >> 12) & 0x3F)
    if slot == "speed4":
        return (word >> 4) & 0x3F
    raise ValueError(f"unknown slot {slot!r}")


def bit21(word: int) -> int:
    return (word >> 21) & 1


def sched_run(blob: bytes, off: int):
    """BE16 words from `off` while they stay in the schedule domain
    (0x600..0x8ff) -- task-02 domain; stops at the first outsider."""
    out = []
    i = off
    while 0 <= i <= len(blob) - 2:
        w = struct.unpack_from(">H", blob, i)[0]
        if not 0x600 <= w <= 0x8FF:
            break
        out.append(w)
        i += 2
    return out


def sect_of(path: str, explicit: str | None = None):
    if explicit:
        return int(explicit, 16)
    m = SECT_RE.search(Path(path).name)
    return int(m.group(1), 16) if m else None


def run_pair(fa: str, fb: str, sect: str) -> int:
    a = Path(fa).read_bytes()
    b = Path(fb).read_bytes()
    s = sect_of(fa, sect)
    d = diff_sections(a, b)
    print(f"== pair {Path(fa).name} <-> {Path(fb).name} sect="
          f"{hex(s) if s is not None else '?'} sizes=({len(a)},{len(b)})"
          f" ndiff={len(d)}")
    unknown = 0
    for off, va, vb in d:
        label = classify(s, off) if s is not None else UNKNOWN
        if label == UNKNOWN:
            unknown += 1
        print(f"   +0x{off:03x}: {va:02x} -> {vb:02x}  [{label}]")
    if len(a) != len(b):
        print(f"   NOTE size mismatch: common prefix {min(len(a), len(b))} B")
    verdict = ("all diffs classified (known fields only)"
               if not unknown else
               f"{unknown} UNCLASSIFIED byte(s) -- non-config speed-data "
               f"candidate(s), GC-3 check required")
    print(f"   -> {verdict}")
    return 1 if unknown else 0


def run_rate_scan(paths) -> int:
    for p in paths:
        blob = Path(p).read_bytes()
        hits = rate_scan(blob)
        print(f"== rate-scan {Path(p).name} ({len(blob)} B): {len(hits)} hits")
        for off, nm, v, tag, ctx in hits:
            print(f"   +0x{off:03x} {nm} {v:6d} [{tag}] ctx {ctx}")
    return 0


def run_window(word_s: str, family: str) -> int:
    w = int(word_s, 16)
    print(f"== window word 0x{w:08x} family={family}")
    print(f"   speeds123 = {window_fields(w, 'speeds123')}")
    print(f"   speed4    = {window_fields(w, 'speed4')}")
    print(f"   bit21 raw = {bit21(w)}"
          "  (LX feature-gate, raw, no interpretation)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="section .bin dumps")
    ap.add_argument("--sect", metavar="0xNN",
                    help="section id override (else from filename suffix)")
    ap.add_argument("--rate-scan", action="store_true",
                    help="rate-scan every FILE instead of pair diff")
    ap.add_argument("--window", metavar="0xWORD",
                    help="decode a 32-bit window word (prints both slots)")
    args = ap.parse_args(argv)

    if args.window:
        w_s, _, slot = args.window.partition(":")
        return run_window(w_s, "lx")
    if args.rate_scan:
        if not args.files:
            print("no files for --rate-scan", file=sys.stderr)
            return 2
        return run_rate_scan(args.files)
    if len(args.files) == 2:
        return run_pair(args.files[0], args.files[1], args.sect)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
