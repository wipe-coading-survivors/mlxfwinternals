#!/usr/bin/env python3
# Референсный пробник для docs/250-re/110-signing/010-payload.md: пересчёт SHA-256 (секция 0xA0) по
# образу с маскировкой magic/устр.-записей/0xA0; бит-в-бит расчёт — открыт
# (маски/size), см. docs/250-re/110-signing/010-payload.md. Верифицирован 2026-09-06 по refs/fw.
import struct, sys, hashlib
from toc_probe import ITOC_HDR, find_all, bits, SECT_NAMES

def main():
    path = sys.argv[1]
    buf = bytearray(open(path,'rb').read())
    toc = find_all(buf, ITOC_HDR)[0]
    # parse entries
    entries = {}
    i = 0
    while i < 64:
        e = toc + 32 + i*32
        if e+32 > len(buf): break
        ent = bytes(buf[e:e+32])
        typ = bits(ent, 0, 8)
        if typ == 0xFF: break
        size = bits(ent, 8, 22)
        flash_addr = bits(ent, 161, 29)
        dev = bits(ent, 206, 1)  # FS3 device_data bit
        entries[typ] = dict(size=size, flash_addr=flash_addr, dev=dev, entry_off=e)
        i += 1
    sig256 = entries[0xA0]
    stored = bytes(buf[sig256['flash_addr']*4 : sig256['flash_addr']*4+32])
    print(f"0xA0: entry@{sig256['entry_off']:#x} data@{sig256['flash_addr']*4:#x} size={sig256['size']*4:#x}")
    print(f"stored digest(32B): {stored.hex()}")
    print(f"total file size = {len(buf):#x}")
    # candidates: imgStart=0, size in set
    for size_name, size in [("4MB", 0x400000), ("16MB", 0x1000000), ("full", len(buf)), ("2MB", 0x200000)]:
        imgStart = 0
        img = bytearray(buf[imgStart: imgStart+size])
        # mask magic 16B
        img[0:16] = b'\xff'*16
        # mask device TOC entries
        for t, en in entries.items():
            if en['dev']:
                off = en['entry_off'] - imgStart
                img[off:off+32] = b'\xff'*32
        # mask 0xA0 entry + data
        eoff = sig256['entry_off'] - imgStart
        img[eoff:eoff+32] = b'\xff'*32
        da = sig256['flash_addr']*4 - imgStart
        img[da: da + sig256['size']*4] = b'\xff' * (sig256['size']*4)
        d = hashlib.sha256(bytes(img)).digest()
        match = "MATCH" if d == stored else "no"
        print(f"  size={size_name:>5} ({size:#x}): sha256={d.hex()[:32]}... {match}")

if __name__ == "__main__":
    main()
