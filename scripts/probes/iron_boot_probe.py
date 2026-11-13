#!/usr/bin/env python3
# Референсный пробник: «IRON»-часть бут-цепочки ConnectX (FS3/FS4).
# Для каждого образа печатает: (1) таблицу boot-секций ITOC
# (type/имя/flash-size/load=param0/entry=param1-param0/presence),
# (2) результат байт-поиска SHA-256/SHA-512 K-констант (полные таблицы
# и префиксы) и начальных хешей H0-H7 (BE/LE) в кодовых секциях,
# RESET_INFO (0x20) и boot-регионе [0x0..ITOC).
# Парсер — в стиле toc_probe (маги, ITOC-записи, битовые поля).
# Без внешних зависимостей. usage: python3 scripts/probes/iron_boot_probe.py <img> [img2 ...]
import struct, sys

from toc_probe import FS3_MAGIC, FS4_MAGIC, ITOC_HDR, find_all, bits, SECT_NAMES

# Кодовые секции «ASIC code» (docs/250-re/100-formats/020-fs3-sections.md: 0x01-0x07, 0x0a-0x0e, 0x15, 0x20)
BOOT_TYPES = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
              0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x15, 0x20]

# SHA-512 K0-K79 (FIPS 180-4), u64
K512_WORDS = [
    0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
    0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
    0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
    0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
    0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
    0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
    0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
    0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
    0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
    0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
    0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
    0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
    0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817]
K512 = struct.pack(">80Q", *K512_WORDS)
# SHA-256 K0-K63 — старшие 32 бита K512[i] (FIPS 180-4: кубические корни тех
# же простых чисел), полная таблица 256B
K256 = struct.pack(">64I", *[w >> 32 for w in K512_WORDS[:64]])
# Начальные хеши. H256 отдельной таблицей НЕ ищется: 8 слов H256 — старшие
# 32 бита слов H512 (математически), и в образах они найдены только внутри
# H512-таблицы (со 16-байтовым шагом), а не как непрерывный 32B-блок.
H512_BE = struct.pack(">8Q", 0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,
                      0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,
                      0x1f83d9abfb41bd6b,0x5be0cd19137e2179)
H512_LE = struct.pack("<8Q", 0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,
                      0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,
                      0x1f83d9abfb41bd6b,0x5be0cd19137e2179)

PATTERNS = [
    ("SHA256-K(64x4B)", K256),
    ("SHA256-K0-15(16x4B)", K256[:64]),
    ("SHA512-K(80x8B)", K512),
    ("SHA512-K0-7(8x8B)", K512[:64]),
    ("SHA512-K8-15(8x8B)", K512[64:128]),
    ("SHA512-H(BE)", H512_BE),
    ("SHA512-H(LE)", H512_LE),
]

def parse_entries(buf, toc, fs4):
    out = []
    i = 0
    while i < 64:
        e = toc + 32 + i*32
        if e + 32 > len(buf): break
        ent = buf[e:e+32]
        typ = bits(ent, 0, 8)
        if typ == 0xFF: break
        size = bits(ent, 8, 22) * 4
        clcrc = bits(ent, 33, 1)
        param0 = bits(ent, 34, 30)
        param1 = struct.unpack_from(">I", ent, 8)[0]
        flash_addr = bits(ent, 161, 29) * 4
        out.append(dict(idx=i, type=typ, size=size, clcrc=clcrc,
                        param0=param0, param1=param1, addr=flash_addr))
        i += 1
    return out

def decrc(data, linesz=64, crcsz=4):
    # MAIN_CODE (FS3 и FS4): в флеше каждая строка = 64B данных + 4B CRC;
    # здесь — представление кода без CRC (docs/250-re/100-formats/030-fs4.md; для FS3 —
    # эмпирически, mstflint FS3 line-CRC не удаляет).
    out = bytearray()
    full = len(data) // (linesz + crcsz)
    for i in range(full):
        off = i * (linesz + crcsz)
        out += data[off:off + linesz]
    return bytes(out)

def search_in(buf, region, name, base):
    hits = []
    for pname, pat in PATTERNS:
        off = region.find(pat)
        while off != -1:
            hits.append((pname, base + off))
            off = region.find(pat, off + 1)
    # Подавить префикс-хиты, если полная таблица найдена в том же месте
    sup = set()
    for pname, off in list(hits):
        if pname == "SHA256-K(64x4B)":
            sup.add(("SHA256-K0-15(16x4B)", off))
        if pname == "SHA512-K(80x8B)":
            sup |= {("SHA512-K0-7(8x8B)", off), ("SHA512-K8-15(8x8B)", off + 64)}
    return [h for h in hits if h not in sup]

def main():
    for path in sys.argv[1:]:
        buf = open(path, "rb").read()
        print(f"== {path.split('/')[-1]} ({len(buf)} bytes)")
        fs4 = None
        m4 = find_all(buf, FS4_MAGIC)
        m3 = find_all(buf, FS3_MAGIC)
        if buf[:16] == FS4_MAGIC: fs4 = True
        elif buf[:16] == FS3_MAGIC: fs4 = False
        else:
            print("  no image magic @0x0"); continue
        print(f"  format: {'FS4' if fs4 else 'FS3'}")
        toc = find_all(buf, ITOC_HDR)[0]
        print(f"  ITOC @ {toc:#x}")
        ents = parse_entries(buf, toc, fs4)
        by_type = {}
        for e in ents: by_type.setdefault(e["type"], []).append(e)

        print(f"  {'type':<6}{'name':<18}{'flash-size':>12}{'code-size':>12}{'flash-addr':>13}"
              f"{'load(p0)':>13}{'entry(p1-p0)':>14}")
        for t in BOOT_TYPES:
            for e in by_type.get(t, []):
                sz = e["size"]
                codesz = f"{int(sz*64/68):#x}" if e["clcrc"] else "-"
                entry = (e["param1"] - e["param0"]) if e["param0"] else 0
                p0 = f"{e['param0']:#x}" if e["param0"] else "-"
                print(f"  {t:#06x}{SECT_NAMES.get(t,'?'):<18}{sz:#12x}{codesz:>12}{e['addr']:#13x}"
                      f"{p0:>13}{entry:#14x}")
        missing = [t for t in BOOT_TYPES if t not in by_type]
        print(f"  missing boot types: {[hex(t) for t in missing]}")

        # Поиск K/H-констант: кодовые секции (сырые flash-байты; для
        # clcrc — также представление без CRC), RESET_INFO, boot-регион
        # [0x0..ITOC), и весь образ (карта хитов).
        regions = []
        for e in ents:
            if e["type"] in BOOT_TYPES:
                name = f"sec {e['type']:#04x} {SECT_NAMES.get(e['type'],'?')}"
                if e["clcrc"]:
                    # CPU видит код без line-CRC (FS3 и FS4): de-clcrc-вид
                    regions.append((name + " [code]", e["addr"],
                                    decrc(buf[e["addr"]:e["addr"]+e["size"]]), e["addr"]))
                else:
                    regions.append((name, e["addr"], buf[e["addr"]:e["addr"]+e["size"]], None))
        regions.append(("boot-region[0x0..ITOC)", 0, buf[0:toc], None))
        print("  SHA-constant search (K256/K512/H0-H7, BE+LE):")
        total = 0
        for name, base, region, decrc_base in regions:
            for pname, roff in search_in(buf, region, name, 0):
                if decrc_base is None:
                    print(f"    {name:<34} {pname:<18} flash@ {base+roff:#x}")
                else:
                    foff = decrc_base + roff + (roff // 64) * 4
                    print(f"    {name:<34} {pname:<18} code@ {roff:#x} (flash~ {foff:#x})")
                total += 1
        if total == 0:
            print("    (no hits in boot sections / RESET_INFO / boot region)")
        # Весь образ: сырые байты + de-clcrc-вид MAIN_CODE (CPU-вид);
        # сырые хиты внутри clcrc-секции, дублирующие code-хиты, не печатаем.
        clcrc_ranges = [(e["addr"], e["addr"] + e["size"]) for e in ents
                        if e["clcrc"]]
        allhits = {}
        for pname, off in search_in(buf, buf, "whole-image", 0):
            if any(lo <= off < hi for lo, hi in clcrc_ranges):
                continue
            allhits.setdefault((pname, off), None)
        for e in ents:
            if e["clcrc"]:
                d = decrc(buf[e["addr"]:e["addr"]+e["size"]])
                for pname, roff in search_in(buf, d, "whole-image", 0):
                    foff = e["addr"] + roff + (roff // 64) * 4
                    if (pname, foff) not in allhits:
                        allhits[(pname, foff)] = "[no-clcrc]"
        if allhits:
            print("  whole-image hits:")
            for (pname, off), tag in allhits.items():
                sect = "?"
                for e in ents:
                    if e["addr"] <= off < e["addr"] + e["size"]:
                        sect = f"sec {e['type']:#04x} {SECT_NAMES.get(e['type'],'?')} (+{off-e['addr']:#x})"
                        break
                if off < toc: sect = "boot-region"
                print(f"    {pname:<18} @ {off:#x}  {sect} {tag or ''}")
        print()

if __name__ == "__main__":
    main()
