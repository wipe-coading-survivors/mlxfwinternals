#!/usr/bin/env python3
# Референсный пробник для docs/250-re/110-signing/005-mechanism.md: секции подписи (0xA0/0xA1/0xA3/0xA4/
# 0xA5/0xA6/0xA7) + флаги IMAGE_INFO (mcc/signed/secure) по набору образов.
# Верифицирован 2026-09-06 по refs/fw.
import struct, sys, os

from toc_probe import FS3_MAGIC, FS4_MAGIC, ITOC_HDR, find_all, bits, SECT_NAMES

SIG_SECTS = [0xA0, 0xA1, 0xA3, 0xA4, 0xA6, 0xA7, 0xA5]
SIG_LABEL = {0xA0:"SIG_256",0xA1:"PUBK_2048",0xA3:"SIG_512",0xA4:"PUBK_4096",0xA5:"HMAC",0xA6:"FS4_PUBK",0xA7:"FS4_SB_SIGS"}

def populated(data: bytes) -> tuple:
    nz = sum(1 for x in data if x not in (0, 0xFF))
    if nz == 0:
        # all zeros or all ff
        if data and all(x == 0xFF for x in data):
            return 0, "0xFF(empty)"
        return 0, "0x00(empty)"
    return nz, f"POPULATED({nz}B)"

def analyze(path):
    buf = open(path, 'rb').read()
    m3 = find_all(buf, FS3_MAGIC)[:3]; m4 = find_all(buf, FS4_MAGIC)[:3]
    kind = "FS3" if (m3 and not m4) else ("FS4" if m4 else "?")
    # find ITOC
    toc = None; fs4 = (kind == "FS4")
    for off in find_all(buf, ITOC_HDR):
        toc = off; break
    entries = {}
    if toc is not None:
        i = 0
        while i < 64:
            e = toc + 32 + i*32
            if e + 32 > len(buf): break
            ent = buf[e:e+32]
            typ = bits(ent, 0, 8)
            if typ == 0xFF: break
            size = bits(ent, 8, 22)
            flash_addr = bits(ent, 161, 29)
            data = buf[flash_addr*4: flash_addr*4 + size*4]
            entries[typ] = (size, flash_addr, data)
            i += 1
    # IMAGE_INFO
    psid = desc = name = prs = ""
    secure_fw = signed_fw = mcc_en = None
    if 0x10 in entries:
        d = entries[0x10][2]
        # byte[1] bits: 8=mcc_en,14=signed_fw,15=secure_fw  (per connectx4_image_info)
        b1 = d[1]
        mcc_en = (b1 >> 0) & 1
        signed_fw = (b1 >> 6) & 1
        secure_fw = (b1 >> 7) & 1
        psid = d[0x24:0x34].split(b'\x00')[0].decode('latin1')
        desc = d[0x1d0:0x2d0].split(b'\x00')[0].decode('latin1')
        name = d[0x340:0x380].split(b'\x00')[0].decode('latin1')
        prs = d[0x380:0x400].split(b'\x00')[0].decode('latin1')
    return dict(kind=kind, name=name, psid=psid, desc=desc, prs=prs,
                mcc_en=mcc_en, signed_fw=signed_fw, secure_fw=secure_fw, entries=entries)

def main():
    rows = []
    for path in sys.argv[1:]:
        a = analyze(path)
        rows.append((os.path.basename(path), a))
    print(f"{'image':<12} {'kind':<4} {'PSID':<16} {'mcc':<3} {'sfd':<3} {'sfc':<3} | sig sections (nz=populated bytes)")
    for fname, a in rows:
        tag = fname.split('-rel')[0][-11:]
        print(f"{tag:<12} {a['kind']:<4} {a['psid']:<16} {a['mcc_en']!s:<3} {a['signed_fw']!s:<3} {a['secure_fw']!s:<3}")
        print(f"    name={a['name']}  prs={a['prs']}")
        print(f"    desc={a['desc']}")
        for t in SIG_SECTS:
            if t in a['entries']:
                size, addr, data = a['entries'][t]
                nz, st = populated(data)
                print(f"    0x{t:02x} {SIG_LABEL.get(t,'?'):<12} size={size*4:#6x} @{addr*4:#x}  {st}")
        print()

if __name__ == "__main__":
    main()
