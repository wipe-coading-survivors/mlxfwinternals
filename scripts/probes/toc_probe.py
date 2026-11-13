#!/usr/bin/env python3
# Референсный пробник для docs/250-re/100-formats/: маги, поиск ITOC/DTOC, парсинг записей,
# сверка всех CRC (цикл mstflint Crc16 — см. docs/250-re/100-formats/025-crc.md). Базовый модуль
# для fb_probe/sig_probe/verify_sha. Верифицирован 2026-09-06 по refs/fw
# и исходникам mstflint.
import struct, sys

FS3_MAGIC = bytes.fromhex("4D5446578CDFD000DEAD92704154BEEF")
FS4_MAGIC = bytes.fromhex("4D544657ABCDEF00FADE12345678DEAD")
ITOC_HDR  = bytes.fromhex("49544F43" "04081516" "2342CAFA" "BACAFE00")
DTOC_HDR  = bytes.fromhex("44544F43" "04081516" "2342CAFA" "BACAFE00")

SECT_NAMES = {
0x01:"BOOT_CODE",0x02:"PCI_CODE",0x03:"MAIN_CODE",0x04:"PCIE_LINK_CODE",0x05:"IRON_PREP_CODE",
0x06:"POST_IRON_BOOT",0x07:"UPGRADE_CODE",0x08:"HW_BOOT_CFG",0x09:"HW_MAIN_CFG",0x0A:"PHY_UC_CODE",
0x0B:"PHY_UC_CONSTS",0x0C:"PCIE_PHY_UC_CODE",0x0D:"CCIR_INFRA",0x0E:"CCIR_ALGO",
0x0F:"FS4_BOOT3_CODE",0x10:"IMAGE_INFO",0x11:"FW_BOOT_CFG",0x12:"FW_MAIN_CFG",0x14:"APU_KERNEL",
0x15:"ACE_CODE",0x17:"ISSU_NOTCH_CFG",0x18:"ROM_CODE",0x20:"RESET_INFO",0x21:"PROG_FW_META",
0x22:"PROG_FW_BIN",0x2A:"PRE_LINK_CODE",0x2B:"PRE_LINK_DATA",0x2C:"POST_LINK_CODE",
0x2D:"POST_LINK_DATA",0x30:"DBG_LOG_MAP",0x32:"DBG_FW_PARAMS",0x33:"FW_ADB",0x34:"GB_FW_CODE",
0x35:"TILE_FW_CODE",0x36:"FS4_FW_TILE_INI",0x37:"FS4_HW_TILE_INI",0x39:"FS4_ISSU_MAIN_UID",
0x3A:"FS4_TILE_UID",0x40:"SLOT_DEPENDENT_INI",0xA0:"SIG_256",0xA1:"PUB_KEYS_2048",0xA2:"FORBIDDEN_VER",
0xA3:"SIG_512",0xA4:"PUB_KEYS_4096",0xA5:"HMAC_DIGEST",0xA6:"FS4_RSA_PUB_KEY",0xA7:"FS4_RSA4096_SIGS",
0xA9:"ENC_KEY_TRANS",0xAA:"FS4_PXIR_INI",0xAB:"FS4_PXIR_INI2",0xAD:"NVDA_ROT_CERTS",
0xE0:"MFG_INFO",0xE1:"DEV_INFO",0xE2:"NV_DATA1",0xE3:"VPD_R0",0xE4:"NV_DATA2",0xE5:"FW_NV_LOG",
0xE6:"NV_DATA0",0xE7:"FS4_DEV_INFO1",0xE8:"FS4_DEV_INFO2",0xE9:"FS4_DEV_INFO3",0xEA:"FS4_DEV_INFO4",
0xFF:"END"}

def crc16_mlx(data: bytes) -> int:
    def step(crc, bit):
        msb = (crc >> 15) & 1
        crc = ((crc << 1) | bit) & 0xFFFF
        if msb:
            crc ^= 0x100B
        return crc
    crc = 0xFFFF
    for b in data:
        for i in range(7, -1, -1):
            crc = step(crc, (b >> i) & 1)
    for _ in range(16):
        crc = step(crc, 0)
    return crc ^ 0xFFFF

def bits(buf, off, n):
    v = 0
    for i in range(n):
        v = (v << 1) | ((buf[off // 8 + (off % 8 + i) // 8] >> (7 - (off % 8 + i) % 8)) & 1)
    return v

def find_all(buf, pat):
    out, i = [], buf.find(pat)
    while i != -1:
        out.append(i); i = buf.find(pat, i + 1)
    return out

def parse_toc(buf, off, fs4: bool):
    hdr = buf[off:off+32]
    stored = bits(hdr, 240, 16)
    calc = crc16_mlx(hdr[:28])
    ok = "OK" if stored == calc else f"CRC MISMATCH stored={stored:#06x} calc={calc:#06x}"
    extra = ""
    if fs4:
        extra = f" flash_layout_ver={bits(hdr,128,8)} ver={bits(hdr,152,8)} num_entries={bits(hdr,184,8)}"
    else:
        extra = f" ver={bits(hdr,152,8)}"
    print(f"  header@{off:#x}: sig={hdr[:4].decode(errors='replace')} {ok}{extra}")
    i = 0
    while i < 64:
        e = off + 32 + i*32
        if e + 32 > len(buf): break
        ent = buf[e:e+32]
        typ = bits(ent, 0, 8)
        if typ == 0xFF:
            print(f"    [{i:2d}] END"); break
        size = bits(ent, 8, 22)
        zipped = bits(ent, 32, 1); clcrc = bits(ent, 33, 1)
        param0 = bits(ent, 34, 30); param1 = struct.unpack_from(">I", ent, 8)[0]
        flash_addr = bits(ent, 161, 29)
        stored_crc = bits(ent, 240, 16)
        calc_crc = crc16_mlx(ent[:28])
        cok = "OK" if stored_crc == calc_crc else f"CRC-BAD {stored_crc:#06x}/{calc_crc:#06x}"
        sec_crc = bits(ent, 208, 16)
        if fs4:
            ver = bits(ent, 144, 16)
            enc = bits(ent, 192, 1); crcf = bits(ent, 205, 3)
            flags = f"z={zipped} clcrc={clcrc} ver={ver:#05x} enc={enc} crcf={crcf:#4x}"
        else:
            rel = bits(ent, 160, 1); no_crc = bits(ent, 207, 1); dev = bits(ent, 206, 1)
            flags = f"z={zipped} clcrc={clcrc} rel={rel} no_crc={no_crc} dev={dev}"
        name = SECT_NAMES.get(typ, "?")
        print(f"    [{i:2d}] 0x{typ:02x} {name:<16} size={hex(size*4):>10} addr={hex(flash_addr*4):>11} p0={hex(param0)} sec_crc={sec_crc:#06x} {cok:<28} {flags}")
        i += 1

def main():
    for path in sys.argv[1:]:
        buf = open(path,'rb').read()
        print(f"== {path.split('/')[-1]} ({len(buf)} bytes)")
        m3 = find_all(buf, FS3_MAGIC)[:5]; m4 = find_all(buf, FS4_MAGIC)[:5]
        if m3: print(f"  FS3 magic @ {[hex(x) for x in m3]}")
        if m4: print(f"  FS4 magic @ {[hex(x) for x in m4]}")
        if m3 and not m4:
            dw9 = struct.unpack_from(">I", buf, 0x24)[0] if m3[0] == 0 else None
            if dw9 is not None:
                print(f"  boot hdr: log2_chunk={((dw9>>16)&0xFF)} binVer={((dw9>>8)&0xFF)}.{dw9&0xFF}")
            kind = "FS3"
        elif m4:
            kind = "FS4"
        else:
            print("  no image magic found"); continue
        for off in find_all(buf, ITOC_HDR):
            print(f"  ITOC @ {off:#x}"); parse_toc(buf, off, kind == "FS4")
        for off in find_all(buf, DTOC_HDR):
            print(f"  DTOC @ {off:#x}"); parse_toc(buf, off, True)
        print()

if __name__ == "__main__":
    main()
