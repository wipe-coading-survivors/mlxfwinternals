#!/usr/bin/env python3
import sys
def load(p):
    return open(p, "rb").read()
dump = load(sys.argv[1])
v5q  = load(sys.argv[2])
v5o  = load(sys.argv[3])
N = len(dump)
def dist(b, lo, hi):
    reg = b[lo:hi]
    z = reg.count(0); ff = reg.count(0xff); other = len(reg) - z - ff
    return "len=%d zero=%d ff=%d other=%d" % (len(reg), z, ff, other)
def diffcount(a, b, lo, hi):
    return sum(1 for i in range(lo, hi) if a[i] != b[i])
regions = [
    ("body  [0x000000,0x557660)", 0x000000, 0x557660),
    ("gap   [0x557660,0xf90000)", 0x557660, 0xf90000),
    ("tail  [0xf90000,0x1000000)", 0xf90000, 0x1000000),
]
for name, lo, hi in regions:
    print("==", name)
    print("   dump:", dist(dump, lo, hi))
    print("   v5q :", dist(v5q,  lo, hi))
    print("   v5o :", dist(v5o,  lo, hi))
    print("   diff dump^v5q=%d  dump^v5o=%d  v5q^v5o=%d" % (
        diffcount(dump, v5q, lo, hi), diffcount(dump, v5o, lo, hi), diffcount(v5q, v5o, lo, hi)))
# show first 32 bytes of tail for each
print("=== tail first 32 bytes (hex) ===")
for nm, b in (("dump", dump), ("v5q", v5q), ("v5o", v5o)):
    print("   %s: %s" % (nm, b[0xf90000:0xf90020].hex()))
# where in tail do dump and v5q first/last differ
lo, hi = 0xf90000, 0x1000000
fd = ld = None
for i in range(lo, hi):
    if dump[i] != v5q[i]:
        if fd is None: fd = i
        ld = i
print("tail dump^v5q: first=0x%06x last=0x%06x" % (fd, ld) if fd else "tail dump^v5q: equal")
