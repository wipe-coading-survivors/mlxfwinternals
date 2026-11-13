#!/usr/bin/env python3
# Diff DTOC-секций (device data) между двумя FS4-образами.
# Использование: dtoc_diff.py <img1> <img2> [--hex <section_name>]
import sys, struct
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from toc_probe import DTOC_HDR, find_all, bits

def parse_dtoc(buf):
    off = find_all(buf, DTOC_HDR)[0]
    entries = []
    i = 0
    while i < 64:
        e = off + 32 + i * 32
        if e + 32 > len(buf):
            break
        ent = buf[e:e+32]
        typ = bits(ent, 0, 8)
        if typ == 0xFF:
            break
        size = bits(ent, 8, 22) * 4
        addr = bits(ent, 161, 29) * 4
        entries.append((typ, addr, size))
        i += 1
    return entries

def main():
    a = open(sys.argv[1], "rb").read()
    b = open(sys.argv[2], "rb").read()
    ea, eb = parse_dtoc(a), parse_dtoc(b)
    print(f"== {sys.argv[1].split('/')[-1]}")
    for t, ad, sz in ea:
        print(f"   0x{t:02x} @ {ad:#010x} size={sz:#x}")
    print(f"== {sys.argv[2].split('/')[-1]}")
    for t, ad, sz in eb:
        print(f"   0x{t:02x} @ {ad:#010x} size={sz:#x}")
    print()
    for (ta, ada, sza), (tb, adb, szb) in zip(ea, eb):
        if ta != tb:
            print(f"[!] section type mismatch: 0x{ta:02x} vs 0x{tb:02x}")
            continue
        da, db = a[ada:ada+sza], b[adb:adb+szb]
        n = min(len(da), len(db))
        diff = [i for i in range(n) if da[i] != db[i]]
        if len(da) != len(db):
            print(f"[!] 0x{ta:02x}: size mismatch {len(da):#x} vs {len(db):#x}")
        if not diff:
            print(f"    0x{ta:02x}: identical")
            continue
        # сгруппировать в диапазоны
        ranges, s, p = [], diff[0], diff[0]
        for x in diff[1:]:
            if x == p + 1:
                p = x
            else:
                ranges.append((s, p)); s, p = x, x
        ranges.append((s, p))
        print(f"    0x{ta:02x}: {len(diff)} diff bytes, {len(ranges)} ranges")
        for s, p in ranges[:16]:
            ra, rb = da[s:p+1], db[s:p+1]
            print(f"      @{ada+s:#010x}: {ra.hex(' ')}  vs  {rb.hex(' ')}")
        if len(ranges) > 16:
            print(f"      ... +{len(ranges)-16} more ranges")

if __name__ == "__main__":
    main()
