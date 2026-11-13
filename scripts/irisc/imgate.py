#!/usr/bin/env python3
"""Image-gate: byte-compare a flash dump against an image file OUTSIDE the gap.

Gap = 0x557660..0xF90000 (unused tail: flash 0x00 vs file 0xFF). Full-file md5
is NOT the gate. Exit 0 = equal out-of-gap (image on flash), 1 = mismatch, 2 = usage.
"""
import sys, hashlib

GAP_START = 0x557660
GAP_END = 0xF90000

def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

def main():
    if len(sys.argv) != 3:
        print("usage: imgate.py DUMP IMAGE", file=sys.stderr)
        return 2
    dump, image = sys.argv[1], sys.argv[2]
    db = open(dump, "rb").read()
    ib = open(image, "rb").read()
    print("dump  %s size=%d md5=%s" % (dump, len(db), md5(dump)))
    print("image %s size=%d md5=%s" % (image, len(ib), md5(image)))
    if len(db) != len(ib):
        print("SIZE MISMATCH: dump=%d image=%d" % (len(db), len(ib)))
        return 1
    n = len(db)
    # out-of-gap ranges: [0, GAP_START) and [GAP_END, n)
    regions = [(0, GAP_START), (GAP_END, n)]
    total_diff = 0
    first_diff = None
    for (lo, hi) in regions:
        if lo >= hi:
            continue
        a, b = db[lo:hi], ib[lo:hi]
        for i in range(hi - lo):
            if a[i] != b[i]:
                total_diff += 1
                if first_diff is None:
                    first_diff = lo + i
    print("gap=0x%06x..0x%06x" % (GAP_START, GAP_END))
    print("out-of-gap ranges: [0x000000..0x%06x) [0x%06x..0x%06x)" % (GAP_START, GAP_END, n))
    if total_diff == 0:
        print("IMAGE-GATE PASS: dump == image out-of-gap (0 differing bytes)")
        return 0
    print("IMAGE-GATE FAIL: %d differing bytes out-of-gap, first @ 0x%06x" % (total_diff, first_diff))
    return 1

if __name__ == "__main__":
    sys.exit(main())
