#!/usr/bin/env python3
# Пробник: по каждой секции ITOC/DTOC — размер, head-гекс, авто-классификация
# (iRISC-код / данные-таблица / zlib / option ROM / crypto / erased / zero /
# empty) + структурированная мета известных секций (PSID, keypair_uuid,
# vendor:device ROM). FS3+FS4. Дополнение к toc_probe (сигнатуры/CRC) — даёт
# домен выполнения и внутреннюю сигнатуру каждой секции офлайн.
# Верифицирован 2026-09-20 по refs/fw (CX-6Dx AC/CX-5/CX-6/CX-4 FS3).
import struct, sys, math
from collections import Counter

from toc_probe import (FS3_MAGIC, FS4_MAGIC, ITOC_HDR, DTOC_HDR,
                       SECT_NAMES, bits, find_all)

# iRISC: opcode = биты 26..31 старшего BE u32; набор разобранных op
# (docs/superpowers/journal 2026-09-14-ghidra-irisc-decode).
IRISC_OPS = (set(range(0x00, 0x05)) | {0x0C, 0x0D} | set(range(0x10, 0x15))
             | set(range(0x17, 0x1D)) | {0x1E, 0x25} | set(range(0x28, 0x2C))
             | {0x32, 0x3F})
IRISC_PROLOGUE = bytes.fromhex("480300bc")   # типичный пролог iRISC-функции

CODE_TYPES  = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x0D,0x0E,0x0F,0x15,
               0x2A,0x2C,0x34,0x35}
PHY_TABLES  = {0x0A,0x0B,0x0C}                # микрокод/константы PHY (данные)
ROM_TYPE    = 0x18
ZLIB_TYPES  = {0x30,0x32,0x33}
SIG_TYPES   = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA9,0xAD}
CERT_NV     = {0xD0,0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,
               0xEA,0xEB,0xEC,0xED,0xEE,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7}

# DTOC-сертификатные типы, отсутствующие в toc_probe.SECT_NAMES (docs/250-re/100-formats/030-fs4.md).
CERT_NAMES = {0xF6:"ROOT_CERTS_1",0xF7:"ROOT_CERTS_2",0xF4:"CERT_CHAINS_1",
              0xF5:"CERT_CHAINS_2",0xF2:"CERT_CHAIN_0",0xED:"DIGITAL_CERT_PTR",
              0xEE:"DIGITAL_CERT_RW",0xF3:"DIGITAL_CERT_CACERT"}
# Официальные имена mstflint flint_base.h (fs3_section_t): правят
# экстраполированные имена в toc_probe.SECT_NAMES (ревью 2026-09-20).
NAME_FIX = {0x30:"DBG_FW_INI", 0xE9:"CRDUMP_MASK_DATA", 0xEA:"FW_INTERNAL_USAGE"}


def entropy(d: bytes) -> float:
    if not d:
        return 0.0
    c = Counter(d); L = len(d)
    return -sum(v / L * math.log2(v / L) for v in c.values())


def irisc_ratio(d: bytes) -> float:
    n = len(d) // 4
    if n == 0:
        return 0.0
    ok = 0
    for i in range(n):
        if ((struct.unpack_from(">I", d, i * 4)[0] >> 26) & 0x3F) in IRISC_OPS:
            ok += 1
    return ok / n


def classify(typ: int, d: bytes) -> str:
    n = len(d)
    if n == 0:
        return "empty"
    if all(b == 0xFF for b in d):
        return "erased"
    if all(b == 0 for b in d):
        return "zero"
    if typ in CODE_TYPES:
        r = irisc_ratio(d)
        if r >= 0.55 and d.find(IRISC_PROLOGUE) != -1:
            return f"iRISC(r={r:.2f},prolog)"
        if r >= 0.55:
            return f"iRISC?(r={r:.2f})"
        return f"code?(r={r:.2f})"
    if typ in PHY_TABLES:
        return "phy-table"
    if typ == ROM_TYPE:
        return "option-rom"
    if typ in ZLIB_TYPES and d[:2] in (b"\x78\xda", b"\x78\x9c", b"\x78\x01", b"\x78\x5e"):
        return "zlib"
    if typ in ZLIB_TYPES:
        return f"data(zlib?{d[:2].hex()})"
    if typ in SIG_TYPES:
        if all(b in (0, 0xFF) for b in d):
            return "erased" if d[0] == 0xFF else "zero"
        return "crypto"
    if typ in CERT_NV:
        return f"data(ent={entropy(d):.2f})"
    return f"data(ent={entropy(d):.2f})"


def _cstr(d: bytes, off: int, n: int) -> str:
    return d[off:off + n].split(b"\x00")[0].decode("ascii", "replace")


def meta(typ: int, d: bytes) -> str:
    n = len(d)
    if n == 0:
        return ""
    if typ == 0x10 and n >= 0x3C:  # IMAGE_INFO: psid@0x24, dev(ven:dev)@0x1c
        v = struct.unpack_from(">I", d, 0x1C)[0]
        return f"psid={_cstr(d,0x24,20)!r} dev={(v & 0xFFFF):04x}:{(v >> 16) & 0xFFFF:04x}"
    if typ == 0xE0 and n >= 0x10:  # MFG_INFO: psid@0x00
        return f"psid={_cstr(d,0,20)!r}"
    if typ == 0xE1:                # DEV_INFO: mDevInfo + CAFABACAFE
        tag = _cstr(d, 0, 10)
        magic = f"magic={d[10:16].hex()}" if n >= 16 else ""
        return f"tag={tag!r} {magic}".strip()
    if typ in (0xA0, 0xA3) and n >= 0x20:  # SIG: sig_uuid@0, keypair_uuid@0x10
        kup = d[0x10:0x20]
        if all(b == 0 for b in kup):
            state = "digest-only"
        elif all(b == 0xFF for b in kup):
            state = "erased"
        else:
            state = "RSA"
        return f"keypair={kup.hex()} [{state}]"
    if typ in (0xA1, 0xA4, 0xA6):  # публичные ключи: есть ли непустой блок
        nz = sum(1 for b in d if b not in (0, 0xFF))
        return f"key({nz}B-nz)"
    if typ == ROM_TYPE:
        i = d.find(b"PCIR")
        if i != -1 and i + 8 <= n:
            ven = struct.unpack_from("<H", d, i + 4)[0]
            dev = struct.unpack_from("<H", d, i + 6)[0]
            fb = d.find(b"FlexBoot")
            fbs = _cstr(d, fb, 32) if fb != -1 else ""
            pe = "PE" if b"PE\x00\x00" in d else "no-PE(packed)"
            return f"PCIR@{i:#x} {ven:04x}:{dev:04x} {fbs!r} {pe}"
        return "no-PCIR"
    if typ in ZLIB_TYPES:
        return f"zlib({d[:2].hex()})" if d[:2] == b"\x78\xda" else f"head={d[:4].hex()}"
    return ""


def parse_entries(buf: bytes, off: int):
    out = []
    for i in range(64):
        e = off + 32 + i * 32
        if e + 32 > len(buf):
            break
        ent = buf[e:e + 32]
        typ = bits(ent, 0, 8)
        if typ == 0xFF:
            break
        size = bits(ent, 8, 22) * 4
        addr = bits(ent, 161, 29) * 4
        out.append((i, typ, addr, size))
    return out


def probe(path: str):
    buf = open(path, "rb").read()
    m4 = find_all(buf, FS4_MAGIC)[:3]
    m3 = find_all(buf, FS3_MAGIC)[:3]
    fs4 = bool(m4)
    kind = "FS4" if fs4 else ("FS3" if m3 else "?")
    print(f"== {path.split('/')[-1]} ({len(buf)} bytes, {kind})")
    tocs = []
    for o in find_all(buf, ITOC_HDR):
        tocs.append(("ITOC", o))
    if fs4:
        for o in find_all(buf, DTOC_HDR):
            tocs.append(("DTOC", o))
    for name, o in tocs:
        print(f"  {name} @{o:#x}")
        for i, typ, addr, size in parse_entries(buf, o):
            d = buf[addr:addr + size]
            dom = classify(typ, d)
            m = meta(typ, d)
            nm = NAME_FIX.get(typ) or SECT_NAMES.get(typ) or CERT_NAMES.get(typ, "?")
            extra = f"  {m}" if m else ""
            print(f"    [{i:2d}] 0x{typ:02x} {nm:<16} {size:>9}  {dom:<22}{extra}")
    print()


def main():
    if len(sys.argv) < 2:
        print("usage: section_meta_probe.py <fw-image.bin> [<fw-image.bin> ...]")
        sys.exit(1)
    for p in sys.argv[1:]:
        try:
            probe(p)
        except Exception as ex:
            print(f"== {p}: ERROR {ex}\n")


if __name__ == "__main__":
    main()
