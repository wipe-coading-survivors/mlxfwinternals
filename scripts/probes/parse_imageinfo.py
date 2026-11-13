#!/usr/bin/env python3
# Референсный пробник для docs/250-re/110-signing/025-secure-boot.md: дамп IMAGE_INFO + диф FW_BOOT_CFG и
# секций подписи для пары образов (создан под CX-6Dx AE/AC — офсеты
# секций захардкожены под эту пару). Верифицирован 2026-09-06 по refs/fw.
import sys, struct

def parse_image_info(buf, addr, size, tag):
    d = buf[addr:addr+size]
    print(f"== {tag} IMAGE_INFO @{addr:#x}")
    # image_info struct from cibfw_layouts.h
    ver = struct.unpack_from("<I", d, 0x00)[0]
    print(f"  ver={ver:#010x}")
    # known fields (offsets per image_info in cibfw_layouts.h)
    # let's dump interesting named fields:
    # psid @0x24 (20 bytes ascii)
    psid = d[0x24:0x3c].decode('ascii', 'replace')
    print(f"  psid={psid!r}")
    name = d[0x3c:0x7c].decode('ascii','replace').rstrip('\x00')
    print(f"  name={name!r}")
    desc = d[0x7c:0x17c].decode('ascii','replace').rstrip('\x00')
    print(f"  desc={desc!r}")
    # flags area: print all bytes 0x00-0x24 as u16 BE pairs
    print("  bytes[0x00:0x24] =", d[0:0x24].hex(' '))
    print("  bytes[0x17c:0x200] =", d[0x17c:0x200].hex(' '))
    print()

def main():
    fa, fb = sys.argv[1], sys.argv[2]
    a = open(fa,'rb').read()
    b = open(fb,'rb').read()
    # IMAGE_INFO at 0x6af400 in both (per ITOC)
    parse_image_info(a, 0x6af400, 0x400, "A(unn/E)")
    parse_image_info(b, 0x6af400, 0x400, "B(signed/C)")
    # FW_BOOT_CFG @0x6b0300, size 0x540: find the differing byte region
    da = a[0x6b0300:0x6b0840]; db = b[0x6b0300:0x6b0840]
    diffs = [(i, da[i], db[i]) for i in range(len(da)) if da[i]!=db[i]]
    print(f"FW_BOOT_CFG diffs ({len(diffs)}):")
    for i,x,y in diffs:
        print(f"  @{0x6b0300+i:#x}: A={x:#04x} B={y:#04x}")
    # SIG_256 0xA0 @0x6b2580 (0x140), SIG_512 0xA3 @0x6b3100 (0x240)
    for name, addr, size in [("SIG_256 0xA0", 0x6b2580, 0x140), ("SIG_512 0xA3", 0x6b3100, 0x240), ("FS4_RSA4096_SIGS 0xA7", 0x6b5580, 0x600)]:
        sa = a[addr:addr+size]; sb = b[addr:addr+size]
        nz_a = sum(1 for x in sa if x not in (0,0xFF))
        nz_b = sum(1 for x in sb if x not in (0,0xFF))
        print(f"{name}: A non-{{0,ff}} bytes={nz_a}, B non-{{0,ff}} bytes={nz_b}")
        # first 32 bytes
        print(f"  A[0:32]={sa[:32].hex(' ')}")
        print(f"  B[0:32]={sb[:32].hex(' ')}")

if __name__ == "__main__":
    main()
