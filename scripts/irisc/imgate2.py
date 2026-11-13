#!/usr/bin/env python3
"""Corrected Image-gate: firmware body [0, BODY_END) bit-exact == image file.

Regions (16 MiB flash, slot B @0x800000, mlxfwutil.py SLOT_MTCF_OFF=0x790000 /
SLOT_DTOC_OFF=0x7FF000 -> MTCF@0xF90000 / DTOC@0xFFF000):
  body [0x000000,0x557660)   -> GATE: must be 0 diff vs image file
  gap  [0x557660,0xF90000)   -> unused (flash 0x00, file 0xFF); informational
  tail [0xF90000,0x1000000)  -> MTCF/DTOC (flash populates on burn, file 0x00);
                                informational (expected to differ post-burn)

Usage: imgate2.py <dump> <image>
Exit:  0 = body 0-diff (PASS), 1 = body diff (FAIL), 2 = error
"""
import sys

BODY_END = 0x557660
GAP_END  = 0xF90000
FULL     = 0x1000000


def region_diff(a, b, start, end):
    ra = a[start:end]
    rb = b[start:end]
    if ra == rb:
        return 0, None
    cnt = 0
    first = None
    for i, (x, y) in enumerate(zip(ra, rb)):
        if x != y:
            cnt += 1
            if first is None:
                first = start + i
    return cnt, first


def hx(v):
    return ("0x%06x" % v) if v is not None else "-"


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: imgate2.py <dump> <image>\n")
        return 2
    dump_path, img_path = sys.argv[1], sys.argv[2]
    try:
        with open(dump_path, "rb") as f:
            dump = f.read()
        with open(img_path, "rb") as f:
            img = f.read()
    except OSError as e:
        sys.stderr.write("error reading: %s\n" % e)
        return 2
    if len(dump) != FULL:
        sys.stderr.write("WARN dump size %d != %#x\n" % (len(dump), FULL))
    if len(img) != FULL:
        sys.stderr.write("WARN image size %d != %#x\n" % (len(img), FULL))
    m = min(len(dump), len(img))

    body_n, body_f = region_diff(dump, img, 0, min(BODY_END, m))
    gap_n, gap_f = region_diff(dump, img, BODY_END, min(GAP_END, m))
    tail_n, tail_f = region_diff(dump, img, GAP_END, min(FULL, m))

    print("dump  = %s" % dump_path)
    print("image = %s" % img_path)
    print("  body [0x000000,0x%06x)  diff=%-8d first=%s" % (BODY_END, body_n, hx(body_f)))
    print("  gap  [0x%06x,0x%06x)   diff=%-8d first=%s" % (BODY_END, GAP_END, gap_n, hx(gap_f)))
    print("  tail [0x%06x,0x%06x)   diff=%-8d first=%s" % (GAP_END, FULL, tail_n, hx(tail_f)))
    if body_n == 0:
        print("IMAGE-GATE PASS: body [0,0x%06x) == image (0 differing bytes)" % BODY_END)
        return 0
    print("IMAGE-GATE FAIL: body [0,0x%06x) has %d differing bytes, first @ %s"
          % (BODY_END, body_n, hx(body_f)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
