#!/usr/bin/env python3
# Референсный пробник для docs/250-re/110-signing/025-secure-boot.md: байтовые диф-диапазоны пары образов.
# Верифицирован 2026-09-06 по refs/fw.
import sys, struct

def diff_ranges(a: bytes, b: bytes, max_ranges=200):
    ranges = []
    i = 0
    n = min(len(a), len(b))
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            ranges.append((i, j))
            i = j
        else:
            i += 1
    return ranges[:max_ranges]

def main():
    fa, fb = sys.argv[1], sys.argv[2]
    a = open(fa, 'rb').read()
    b = open(fb, 'rb').read()
    print(f"A: {fa.split('/')[-1]} {len(a)}")
    print(f"B: {fb.split('/')[-1]} {len(b)}")
    ranges = diff_ranges(a, b)
    print(f"\n{len(ranges)} differing ranges (total bytes: {sum(e-s for s,e in ranges)}):")
    for s, e in ranges:
        # show first 16 bytes of each
        sa = a[s:s+16].hex(' ')
        sb = b[s:s+16].hex(' ')
        print(f"  {s:08x}-{e:08x} ({e-s:6d}B)  A: {sa}")
        print(f"  {'':8s}{'':8s}          B: {sb}")

if __name__ == "__main__":
    main()
