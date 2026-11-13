#!/usr/bin/env python3
# Доп. независимое исследование (НЕ часть проекта): сборка гибридного образа
# ConnectX-4 — свежая база FW 14.32.1912 + идентичность/скорости/PCIe нашей
# карты 0x1013. Консервативная стратегия: правятся ТОЛЬКО проверенно-стабильные
# одиночные поля; порт-конфигурация базы (1xQSFP28, serdes 3,2,1,0) не меняется.
#
# База (G)  : fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-...bin
#             0x1015, 1p QSFP28, 50G, x8, EN
# Справочник(A): fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-...bin
#             0x1013, 1p QSFP28, 100G, x16 — наша карта
#
# Правки (все оффсеты верифицированы стабильными между 12.28 и 14.32):
#   IMAGE_INFO(0x10): device_id 0x1c (2B), subsystem 0x20 (2B), PSID 0x24 (14B) <- A
#   FW_MAIN_CFG(0x12): lcl[0] 0x30b = 0xfb (1,10,25,40,50,56,100 G)
#   HW_BOOT_CFG(0x08): PCIe width 0x8b = 0x09 (x16) <- A
# CRC: sec_crc=crc16(секция) в bits 208..223 записи ITOC, entry_crc=crc16(запись[:28])
#      в bits 240..255 (пересчитываются для каждой изменённой секции).
# Подпись RSA при этом ломается — карта non-secure, "Burning FW image without
# signatures" (см. docs/250-re/110-signing/030-root-of-trust.md, docs/850-howto/130-rom-dump).
#
# Использование:
#   python3 upgrade_base.py -b base.bin -a ref.bin -o out.bin [--dry-run] [--check]
import argparse, sys, hashlib
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from toc_probe import crc16_mlx, ITOC_HDR, find_all, bits, SECT_NAMES

# (секция, rel_off, длина, источник)  источник: 'ref' = копировать из A, ( 'lit', val ) = литерал
PATCHES = [
    (0x10, 0x1c, 2,  'ref'),          # device_id  0x1015 -> 0x1013
    (0x10, 0x20, 2,  'ref'),          # subsystem  0x0006 -> 0x0013
    (0x10, 0x24, 14, 'ref'),          # PSID       MT_2430110032 -> MT_2180110032
    (0x12, 0x30b, 1, ('lit', 0xfb)),  # lcl[0]     0x3b(50G) -> 0xfb (100G+56G)
    (0x08, 0x8b, 1,  'ref'),          # PCIe width 0x89(x8) -> 0x09(x16)
]


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
        out[typ] = (e, ent)
        i += 1
    return itoc, out


def sect_range(ent):
    size = bits(ent, 8, 22) * 4
    addr = bits(ent, 161, 29) * 4
    return addr, size


def set_bits(entb, bitpos, n, val):
    for i in range(n):
        b = (val >> (n - 1 - i)) & 1
        p = bitpos + i
        if b:
            entb[p // 8] |= (1 << (7 - p % 8))
        else:
            entb[p // 8] &= ~(1 << (7 - p % 8))


def check_all_crc(buf, label):
    itoc, entries = itoc_entries(buf)
    bad = 0
    for typ, (eoff, ent) in entries.items():
        addr, size = sect_range(ent)
        sec = buf[addr:addr + size]
        sec_crc = bits(ent, 208, 16)
        ent_crc = bits(ent, 240, 16)
        if crc16_mlx(sec) != sec_crc:
            print(f"  SEC-CRC BAD  0x{typ:02x} {SECT_NAMES.get(typ,'?')}: "
                  f"stored={sec_crc:#06x} calc={crc16_mlx(sec):#06x}")
            bad += 1
        if crc16_mlx(ent[:28]) != ent_crc:
            print(f"  ENT-CRC BAD  0x{typ:02x} {SECT_NAMES.get(typ,'?')}: "
                  f"stored={ent_crc:#06x} calc={crc16_mlx(ent[:28]):#06x}")
            bad += 1
    print(f"[{label}] CRC-проверка всех секций: {'OK (0 mismatch)' if bad == 0 else f'{bad} MISMATCH'}")
    return bad


def build(base, ref, dry):
    out = bytearray(base)
    itoc, entries = itoc_entries(base)
    ref_itoc, ref_entries = itoc_entries(ref)
    # кэш range по типу (база и справка — разные flash-адреса!)
    ranges = {t: sect_range(e[1]) for t, e in entries.items()}
    ref_ranges = {t: sect_range(e[1]) for t, e in ref_entries.items()}
    modified = set()
    print("== Пatches:")
    for styp, roff, ln, src in PATCHES:
        if styp not in entries:
            sys.exit(f"секция 0x{styp:02x} не найдена в базе")
        if styp not in ref_entries:
            sys.exit(f"секция 0x{styp:02x} не найдена в справочнике")
        eoff, ent = entries[styp]
        addr, size = ranges[styp]
        if roff + ln > size:
            sys.exit(f"rel 0x{roff:#x}+{ln} выходит за секцию 0x{styp:02x} (size {size:#x})")
        if src == 'ref':
            raddr, rsize = ref_ranges[styp]
            if roff + ln > rsize:
                sys.exit(f"rel 0x{roff:#x}+{ln} выходит за секцию 0x{styp:02x} в A (size {rsize:#x})")
            val = ref[raddr + roff:raddr + roff + ln]  # из A по ЕГО flash_addr
            src_desc = f"ref(A)={val.hex()}"
        else:
            val = bytes([src[1]]) * ln
            src_desc = f"lit=0x{src[1]:02x}"
        old = out[addr + roff:addr + roff + ln]
        new = val
        print(f"  0x{styp:02x} {SECT_NAMES.get(styp,'?'):<14} rel 0x{roff:#04x} abs 0x{addr+roff:#08x}: "
              f"{old.hex()} -> {new.hex()}  [{src_desc}]")
        out[addr + roff:addr + roff + ln] = new
        modified.add(styp)
    if dry:
        print("(dry-run: CRC не пересчитаны, файл не записан)")
        return bytes(out), modified
    # пересчёт CRC изменённых секций
    print("== CRC:")
    for styp in sorted(modified):
        eoff, ent = entries[styp]
        addr, size = ranges[styp]
        old_sec = bits(ent, 208, 16)
        old_ent = bits(ent, 240, 16)
        new_sec = crc16_mlx(bytes(out[addr:addr + size]))
        entb = bytearray(out[eoff:eoff + 32])
        set_bits(entb, 208, 16, new_sec)
        new_ent = crc16_mlx(bytes(entb[:28]))
        set_bits(entb, 240, 16, new_ent)
        out[eoff:eoff + 32] = entb
        print(f"  0x{styp:02x} {SECT_NAMES.get(styp,'?'):<14} sec_crc {old_sec:#06x}->{new_sec:#06x}  "
              f"entry_crc {old_ent:#06x}->{new_ent:#06x}")
    return bytes(out), modified


def verify(out, base, ref):
    print("== Верификация результата:")
    bad = check_all_crc(out, "result")
    itoc, entries = itoc_entries(out)
    ranges = {t: sect_range(e[1]) for t, e in entries.items()}
    print("  identity/speed/pcie в результате:")
    a, s = ranges[0x10]
    print(f"    device_id = {out[a+0x1c]:#04x}{out[a+0x1d]:#04x} "
          f"(0x{out[a+0x1c]:02x}{out[a+0x1d]:02x})")
    print(f"    subsystem = 0x{out[a+0x20]:02x}{out[a+0x21]:02x}")
    print(f"    PSID      = {bytes(out[a+0x24:a+0x24+14]).decode('latin1')}")
    f, fs = ranges[0x12]
    print(f"    lcl[0]    = 0x{out[f+0x30b]:02x} (0xfb = 1,10,25,40,50,56,100G)")
    h, hs = ranges[0x08]
    print(f"    PCIe width= 0x{out[h+0x8b]:02x} (0x09 = x16)")
    return bad == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-b', '--base', required=True, help="база 14.32 (GCA)")
    ap.add_argument('-a', '--ref', required=True, help="справочник 0x1013 (MCX455A)")
    ap.add_argument('-o', '--output')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--check', action='store_true', help="только CRC-проверка базы")
    a = ap.parse_args()
    base = open(a.base, 'rb').read()
    ref = open(a.ref, 'rb').read()
    print(f"== base: {a.base.split('/')[-1]} ({len(base)} B, md5 {hashlib.md5(base).hexdigest()})")
    print(f"== ref : {a.ref.split('/')[-1]} ({len(ref)} B, md5 {hashlib.md5(ref).hexdigest()})")
    if a.check:
        check_all_crc(base, "base")
        return
    bad = check_all_crc(base, "base")
    if bad:
        sys.exit("CRC-модель не верифицирована на базе — abort")
    out, _ = build(base, ref, a.dry_run)
    if a.dry_run:
        return
    ok = verify(out, base, ref)
    if not a.output:
        sys.exit("нужен -o при реальной сборке")
    open(a.output, 'wb').write(out)
    print(f"== записал: {a.output} ({len(out)} B, md5 {hashlib.md5(out).hexdigest()})")
    if not ok:
        sys.exit("верификация НЕ пройдена — проверьте результат перед флешем")
    print("== ГОТОВО: все CRC OK, поля на месте. Проверить ещё: mstflint -i <out> q")


if __name__ == '__main__':
    main()
