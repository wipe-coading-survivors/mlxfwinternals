#!/usr/bin/env python3
# Доп. независимое исследование (НЕ часть проекта): патч бита 56GbE в
# lcl[x].eth_speeds_supported (секция FW_MAIN_CFG) образа CX-5 + пересчёт CRC.
#
# Основание (см. docs/550-poc/100-mlxfwutil/040-probes-catalog.md):
#   * поле живёт в бинарной секции 0x12 (FW_MAIN_CFG), НЕ в текстовом PRS;
#   * битовая карта (верифицирована по CX-5 100G/25G и CX-4 56G):
#       bit0=1G bit1=10G bit2=20G(рез.) bit3=25G bit4=40G bit5=50G
#       bit6=56G bit7=100G
#   * 56G-бит = 0x40. Для 100G-карты lcl-байт = 0xbb -> 0xfb.
#   * CRC: sec_crc = crc16(сырые байты секции) в bits 208..223 записи ITOC;
#     entry_crc = crc16(запись[:28]) в bits 240..255. (верифицировано)
#
# Скрипт НЕ трогает PRS (секция 0x30) и подпись: FW читает бинарный
# FW_MAIN_CFG, текст PRS — артефакт сборки. RSA-подпись при этом ломается —
# вопрос, загрузится ли образ, см. docs/250-re/110-signing/030-root-of-trust.md и docs/850-howto/130-rom-dump (ROM-дамп).
#
# Использование:
#   python3 patch_56g.py -i in.bin -o out.bin [--port 0|1|both] [--dry-run]
#   python3 patch_56g.py -i in.bin --analyze
import argparse, sys, zlib, struct
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from toc_probe import crc16_mlx, ITOC_HDR, find_all, bits

BIT_56G = 0x40  # bit6


def itoc_entries(buf):
    itoc = find_all(buf, ITOC_HDR)[0]
    out = {}
    i = 0
    while True:
        e = itoc + 32 + i * 32
        ent = buf[e:e + 32]
        typ = bits(ent, 0, 8)
        if typ == 0xFF:
            break
        out[typ] = (e, ent)  # entry offset, entry bytes
        i += 1
    return itoc, out


def sect_range(buf, ent):
    size = bits(ent, 8, 22) * 4
    addr = bits(ent, 161, 29) * 4
    return addr, size


def prs_speeds(buf, entries):
    if 0x30 not in entries:
        return None
    _, ent = entries[0x30]
    addr, size = sect_range(buf, ent)
    try:
        txt = zlib.decompress(buf[addr:addr + size]).decode('latin1')
    except Exception:
        return None
    import re
    out = {}
    for m in re.finditer(r"lcl\[(\d+)\]\.eth_speeds_supported\.(\w+)\s*=\s*0x([0-9a-fA-F]+)", txt):
        out.setdefault(int(m.group(1)), {})[m.group(2)] = int(m.group(3), 16)
    return out


def speed_byte_from_prs(p):
    order = ["Speed1Gb", "Speed10Gb", "Speed25Gb", "Speed40Gb",
             "Speed50Gb", "Speed56Gb", "Speed100Gb"]
    b = 0
    for i, k in enumerate(order):
        if p.get(k, 0):
            b |= (1 << i) if i < 2 else (1 << (i + 1))  # bit2=20G сдвигает
    return b


def find_lcl_bytes(sec, expected):
    # ищем пару байт = expected со стридом 0xC (lcl[0], lcl[1])
    hits = []
    i = 0
    while True:
        i = sec.find(bytes([expected]), i)
        if i == -1:
            break
        hits.append(i)
        i += 1
    pairs = [h for h in hits if h + 12 < len(sec) and sec[h + 12] == expected]
    return pairs


def patch(buf, port, dry):
    itoc, entries = itoc_entries(buf)
    if 0x12 not in entries:
        sys.exit("секция 0x12 (FW_MAIN_CFG) не найдена")
    eoff, ent = entries[0x12]
    addr, size = sect_range(buf, ent)
    sec = bytearray(buf[addr:addr + size])

    prs = prs_speeds(buf, entries)
    if prs:
        exp0 = speed_byte_from_prs(prs.get(0, {}))
        print(f"PRS lcl[0] -> ожидаемый байт {exp0:#04x}")
        pairs = find_lcl_bytes(bytes(sec), exp0)
        if not pairs:
            sys.exit(f"lcl-байт {exp0:#04x} (пара со стридом 0xC) не найден в FW_MAIN_CFG")
        base = pairs[0]
    else:
        # PRS нет: ищем 0xbb (стандартный 100G-набор)
        pairs = find_lcl_bytes(bytes(sec), 0xbb)
        if not pairs:
            sys.exit("PRS отсутствует и lcl-байт 0xbb не найден — уточните вручную")
        base = pairs[0]
        exp0 = 0xbb

    targets = []
    if port in (0, 'both'):
        targets.append((base, 0))
    if port in (1, 'both'):
        if base + 12 < len(sec) and sec[base + 12] == exp0:
            targets.append((base + 12, 1))
        elif port == 1:
            sys.exit("lcl[1] не найден")

    new_sec = bytearray(sec)
    for off, p in targets:
        old = new_sec[off]
        new = old | BIT_56G
        print(f"  lcl[{p}] rel 0x{off:#04x} abs 0x{addr + off:#08x}: {old:#04x} -> {new:#04x}")
        new_sec[off] = new  # всегда правим в памяти; запись в файл — ниже

    old_sec_crc = bits(ent, 208, 16)
    new_sec_crc = crc16_mlx(bytes(new_sec))
    old_ent_crc = bits(ent, 240, 16)
    print(f"  sec_crc: {old_sec_crc:#06x} -> {new_sec_crc:#06x}")

    if dry:
        print("  (dry-run: файл не менялся)")
        return buf

    out = bytearray(buf)
    out[addr:addr + size] = new_sec
    # обновить запись ITOC: sec_crc (bits 208..223), затем entry_crc (bits 240..255)
    entb = bytearray(out[eoff:eoff + 32])
    # записать sec_crc в bits 208..223
    for i in range(16):
        bitpos = 208 + i
        if (new_sec_crc >> (15 - i)) & 1:
            entb[bitpos // 8] |= (1 << (7 - bitpos % 8))
        else:
            entb[bitpos // 8] &= ~(1 << (7 - bitpos % 8))
    new_ent_crc = crc16_mlx(bytes(entb[:28]))
    for i in range(16):
        bitpos = 240 + i
        if (new_ent_crc >> (15 - i)) & 1:
            entb[bitpos // 8] |= (1 << (7 - bitpos % 8))
        else:
            entb[bitpos // 8] &= ~(1 << (7 - bitpos % 8))
    out[eoff:eoff + 32] = entb
    print(f"  entry_crc: {old_ent_crc:#06x} -> {new_ent_crc:#06x}")
    return bytes(out)


def analyze(buf):
    itoc, entries = itoc_entries(buf)
    eoff, ent = entries[0x12]
    addr, size = sect_range(buf, ent)
    sec = buf[addr:addr + size]
    prs = prs_speeds(buf, entries)
    print(f"FW_MAIN_CFG @ {addr:#x} size {size:#x}")
    if prs:
        for p in sorted(prs):
            b = speed_byte_from_prs(prs[p])
            print(f"  PRS lcl[{p}] -> {b:#04x}  {prs[p]}")
        exp = speed_byte_from_prs(prs.get(0, {}))
        for h in find_lcl_bytes(sec, exp):
            print(f"  lcl-байт {exp:#04x} @ rel {h:#x} (abs {addr + h:#x})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-i', '--input', required=True)
    ap.add_argument('-o', '--output')
    ap.add_argument('--port', default='both', choices=['0', '1', 'both'])
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--analyze', action='store_true')
    a = ap.parse_args()
    buf = open(a.input, 'rb').read()
    if a.analyze:
        analyze(buf)
        return
    port = a.port if a.port == 'both' else int(a.port)
    out = patch(buf, port, a.dry_run)
    if not a.dry_run:
        if not a.output:
            sys.exit("нужен -o при реальной правке")
        open(a.output, 'wb').write(out)
        print(f"записал: {a.output}")


if __name__ == '__main__':
    main()
