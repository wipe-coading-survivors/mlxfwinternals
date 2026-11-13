#!/usr/bin/env python3
# Референсный пробник для docs/250-re/110-signing/005-mechanism.md и
# 025-secure-boot.md: ITOC (HwPointers/поиск заголовка),
# секции подписи 0xA0-0xA7, IMAGE_INFO, FW_BOOT_CFG — анализ вендорских
# образов (Dell/HP/Facebook). Верифицирован 2026-09-06 по refs/fw.
# История исправлений: keypair_uuid читался с единого офсета 0x18 — неверно
# (по layout: 0x10 у 0xA3/0xA4, 0x04 у 0xA6; см. SIG_LAYOUT); исправлено
# 2026-09-06 по image_layout_layouts.h — вывод совпал с docs/250-re/110-signing/005-mechanism.md.
# Часть функционала дублирует toc_probe/sig_probe (ITOC-лист без CRC, PSID) —
# сводная таблица: README в этом каталоге.
import struct, sys
from toc_probe import FS3_MAGIC, FS4_MAGIC, ITOC_HDR, DTOC_HDR, find_all, bits, crc16_mlx, SECT_NAMES

def hwpointers_toc_off(buf):
    # HwPointers @0x18 : ptr(u64 LE)+crc(u16) x N; toc = ptr[2]
    try:
        p = buf[0x18:]
        for idx in range(8):
            off = idx*16
            ptr = struct.unpack_from("<Q", p, off)[0]
            if 0 < ptr < len(buf):
                if idx == 2:
                    return ptr, "hwpointers[2]"
    except Exception:
        pass
    return None, None

def parse_entries(buf, toc):
    ents = {}
    i = 0
    while i < 128:
        e = toc + 32 + i*32
        if e + 32 > len(buf): break
        ent = buf[e:e+32]
        typ = bits(ent, 0, 8)
        if typ == 0xFF: break
        size = bits(ent, 8, 22)
        flash_addr = bits(ent, 161, 29)
        addr = flash_addr * 4
        data = buf[addr: addr + size*4]
        ents[typ] = (size, flash_addr, data)
        i += 1
    return ents

# Layout по refs/src/mstflint/tools_layouts/image_layout_layouts.h
# (типы секций — mlxfwops/lib/flint_base.h):
#   0xA0/0xA3 image_layout_image_signature[_2]: sig_uuid@0x00, keypair_uuid@0x10, sig@0x20
#   0xA1/0xA4 image_layout_file_public_keys[_2]: keypair_exp@0x0C, keypair_uuid@0x10, key@0x20
#   0xA6     image_layout_file_public_keys_3: keypair_exp@0x00, keypair_uuid@0x04, key@0x14
#   0xA7     image_layout_secure_boot_signatures: boot@0x00, critical@0x200, non_critical@0x400
SIG_LAYOUT = {
    0xA0: (0x00, 0x10, 0x20),
    0xA3: (0x00, 0x10, 0x20),
    0xA1: (None, 0x10, 0x20),
    0xA4: (None, 0x10, 0x20),
    0xA6: (None, 0x04, 0x14),
}

def main():
    for path in sys.argv[1:]:
        buf = open(path,'rb').read()
        print(f"== {path.split('/')[-1]} ({len(buf):#x} bytes)")
        m3 = find_all(buf, FS3_MAGIC)[:3]; m4 = find_all(buf, FS4_MAGIC)[:3]
        kind = "FS3" if (m3 and not m4) else ("FS4" if m4 else "?")
        # ITOC: prefer hwpointers, else header search
        toc, src = hwpointers_toc_off(buf)
        if toc is None:
            off = find_all(buf, ITOC_HDR)
            toc = off[0] if off else None
            src = "ITOC_HDR-search" if off else None
        print(f"  kind={kind} ITOC@{toc and hex(toc)} ({src})")
        if toc is None:
            print("  !! no ITOC\n"); continue
        # header sanity
        hdr = buf[toc:toc+32]
        stored = bits(hdr,240,16); calc = crc16_mlx(hdr[:28])
        print(f"  ITOC hdr: sig={hdr[:4]} CRC {'OK' if stored==calc else 'BAD'} num_entries={bits(hdr,184,8)}")
        ents = parse_entries(buf, toc)
        # IMAGE_INFO PSID (FS4 layout)
        if 0x10 in ents:
            d = ents[0x10][2]
            # FS4 image_info: psid is a 16-byte field; find ascii
            # try common offset 0x24
            for psid_off in (0x24,):
                s = d[psid_off:psid_off+16]
                # strip
                txt = s.split(b'\x00')[0].decode('latin1','replace')
                print(f"  IMAGE_INFO psid@{psid_off:#x} = {txt!r}")
        print("  --- signature sections ---")
        for typ in (0xA0,0xA3,0xA4,0xA6,0xA7):
            if typ not in ents:
                print(f"    0x{typ:02x} {SECT_NAMES.get(typ,'?'):<16} (absent)")
                continue
            size, fa, data = ents[typ]
            if typ == 0xA7:
                for nm, off in (("boot",0x00),("critical",0x200),("non_critical",0x400)):
                    print(f"    0xA7 {SECT_NAMES.get(typ,'?'):<16} {nm}_sig@{off:#x} = {data[off:off+16].hex()}...")
                continue
            su_off, ku_off, payload_off = SIG_LAYOUT[typ]
            su = data[su_off:su_off+16].hex() if su_off is not None else "-"
            ku = data[ku_off:ku_off+16].hex()
            dat = data[payload_off:payload_off+min(32,len(data)-payload_off)]
            print(f"    0x{typ:02x} {SECT_NAMES.get(typ,'?'):<16} size={size*4:#x} sig_uuid={su} keypair_uuid={ku}")
            print(f"        data@{payload_off:#x} = {dat.hex()}")
        # device_id / subsystem from FW_BOOT_CFG (0x11)
        if 0x11 in ents:
            d = ents[0x11][2]
            did = struct.unpack_from(">H", d, 0x2D)[0] if len(d)>0x2F else None
            subs = struct.unpack_from(">I", d, 0x3D)[0] if len(d)>0x41 else None
            print(f"  FW_BOOT_CFG: device_id@0x2D={did and hex(did)} subsystem@0x3D={subs and hex(subs)}")
        print()

if __name__ == "__main__":
    main()
