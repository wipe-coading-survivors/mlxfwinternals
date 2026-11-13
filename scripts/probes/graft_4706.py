#!/usr/bin/env python3
# Доп. независимое исследование (НЕ часть проекта): «апгрейд кода внутри семьи
# 12.28» — берём новый код C (12_28_4706, dual-port MCX456A, 0x1013) и
# переконфигурируем под single-port нашу карту (A = 12_28_2302 MCX455A, 0x1013,
# x16, 100G), разрешая 56G (lcl 0xfb). CX-4Lx (14.32, 0x1015) — другой чип,
# отложен (docs/850-howto/140-fw-upgrade).
#
# A и C — один chip (MT27700), один релиз 12.28, ОДИНАКОВЫЙ layout config-секций
# (сверено: 0x08/0x09/0x11/0x12/0x10 — те же адреса/размеры). Code-секции у C
# больше (MAIN_CODE 0x3090e0->0x30a590) и смещены -> «вырезать код из C в адрес
# A» невозможно; поэтому база = C (self-consistent 4706 layout + код), а
# single-port-конфиг переносим из A. Финал: 1p карта на коде 4706, 100G+56G, x16.
#
# Правки (v2, 2026-09-07). v1 точечно чинил port-поля, но пропускал 0x11:0x35
# (SKU 0x13/0x14) и др. -> карта грузилась как DUAL-port, фантомный port2 вешал
# FW (health err synd 0x7). Надёжнее: копируем ВСЕ config-секции A целиком:
#   0x08 HW_BOOT_CFG : ВСЯ <- A (x16 + config)
#   0x09 HW_MAIN_CFG : ВСЯ <- A (1xQSFP28, serdes 3,2,1,0)
#   0x11 FW_BOOT_CFG : ВСЯ <- A (num_of_ports=1, SKU 0x13, per-port табл.)
#   0x12 FW_MAIN_CFG : ВСЯ <- A (single-port feature table, lcl), затем lcl[0]|=56G
#   0x12 lcl[0] 0x30b: -> 0xfb (100G+56G; A было 0xbb без 56G)
#   0x10 IMAGE_INFO  : sub 0x21 <-A (0x0013), PSID 0x24(14B) <-A (MT_2180110032)
# Version-СТРОКИ 0x10 держим C (mstflint q -> 12.28.4706). CRC для изменённых.
# Подпись ломается — non-secure, burn через --no_fw_ctrl ("without signatures").
#
# Использование:
#   python3 graft_4706.py -b C.bin -a A.bin -o out.bin [--dry-run]
import argparse, sys, hashlib
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from toc_probe import crc16_mlx, ITOC_HDR, find_all, bits, SECT_NAMES

# (секция, rel_off, длина, источник): 'ref'=<A> по rel, ('lit',v)=литерал, 'sect'=вся секция A
PATCHES = [
    (0x08, 0, 0x140, 'sect'),         # вся HW_BOOT_CFG <- A (x16)
    (0x09, 0, 0x1600, 'sect'),        # вся HW_MAIN_CFG <- A (1xQSFP28)
    (0x11, 0, 0x3c0, 'sect'),         # вся FW_BOOT_CFG <- A (1p, SKU 0x13)
    (0x12, 0, 0xc00, 'sect'),         # вся FW_MAIN_CFG <- A (single-port)
    (0x12, 0x30b, 1, ('lit', 0xfb)),  # lcl[0] = 100G+56G (A: 0xbb + 56G)
    (0x10, 0x21, 1, 'ref'),           # subsystem low -> 0x13
    (0x10, 0x24, 14, 'ref'),          # PSID -> MT_2180110032
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
    return bits(ent, 161, 29) * 4, bits(ent, 8, 22) * 4


def set_bits(entb, bitpos, n, val):
    for i in range(n):
        b = (val >> (n - 1 - i)) & 1
        p = bitpos + i
        if b:
            entb[p // 8] |= (1 << (7 - p % 8))
        else:
            entb[p // 8] &= ~(1 << (7 - p % 8))


def check_all_crc(buf, label):
    _, entries = itoc_entries(buf)
    bad = 0
    for typ, (eoff, ent) in entries.items():
        addr, size = sect_range(ent)
        sec = buf[addr:addr + size]
        if crc16_mlx(sec) != bits(ent, 208, 16):
            print(f"  SEC-CRC BAD 0x{typ:02x} {SECT_NAMES.get(typ,'?')}")
            bad += 1
        if crc16_mlx(ent[:28]) != bits(ent, 240, 16):
            print(f"  ENT-CRC BAD 0x{typ:02x} {SECT_NAMES.get(typ,'?')}")
            bad += 1
    print(f"[{label}] CRC всех секций: {'OK (0 mismatch)' if bad == 0 else f'{bad} MISMATCH'}")
    return bad


def build(base, ref, dry):
    out = bytearray(base)
    _, entries = itoc_entries(base)
    _, ref_entries = itoc_entries(ref)
    ranges = {t: sect_range(e[1]) for t, e in entries.items()}
    ref_ranges = {t: sect_range(e[1]) for t, e in ref_entries.items()}
    modified = set()
    print("== Пatches:")
    for styp, roff, ln, src in PATCHES:
        if styp not in entries or styp not in ref_entries:
            sys.exit(f"секция 0x{styp:02x} не найдена")
        addr, size = ranges[styp]
        raddr, rsize = ref_ranges[styp]
        if src == 'sect':
            ln = size
        if roff + ln > size or roff + ln > rsize:
            sys.exit(f"rel 0x{roff:#x}+{ln:#x} за секцию 0x{styp:02x}")
        if src == 'ref':
            val = ref[raddr + roff:raddr + roff + ln]
        elif src == 'sect':
            val = ref[raddr:raddr + ln]
        else:
            val = bytes([src[1]]) * ln
        old = out[addr + roff:addr + roff + ln]
        tag = 'sect(A)' if src == 'sect' else (f"ref(A)={val.hex()}" if src == 'ref' else f"lit=0x{src[1]:02x}")
        if len(old) > 16:
            old_s = old[:8].hex() + '…'
        else:
            old_s = old.hex()
        print(f"  0x{styp:02x} {SECT_NAMES.get(styp,'?'):<14} rel 0x{roff:#05x} abs 0x{addr+roff:#08x} len {ln:#x}: "
              f"{old_s} <- {tag}")
        out[addr + roff:addr + roff + ln] = val
        modified.add(styp)
    if dry:
        print("(dry-run: CRC не пересчитаны, файл не записан)")
        return bytes(out)
    print("== CRC:")
    for styp in sorted(modified):
        eoff, ent = entries[styp]
        addr, size = ranges[styp]
        o_sec, o_ent = bits(ent, 208, 16), bits(ent, 240, 16)
        n_sec = crc16_mlx(bytes(out[addr:addr + size]))
        entb = bytearray(out[eoff:eoff + 32])
        set_bits(entb, 208, 16, n_sec)
        n_ent = crc16_mlx(bytes(entb[:28]))
        set_bits(entb, 240, 16, n_ent)
        out[eoff:eoff + 32] = entb
        print(f"  0x{styp:02x} {SECT_NAMES.get(styp,'?'):<14} sec_crc {o_sec:#06x}->{n_sec:#06x}  "
              f"entry_crc {o_ent:#06x}->{n_ent:#06x}")
    return bytes(out)


def verify(out):
    print("== Верификация:")
    bad = check_all_crc(out, "result")
    _, entries = itoc_entries(out)
    ranges = {t: sect_range(e[1]) for t, e in entries.items()}
    a, _ = ranges[0x10]
    f, _ = ranges[0x12]
    h, _ = ranges[0x08]
    print(f"  device_id  = 0x{out[a+0x1c]:02x}{out[a+0x1d]:02x}")
    print(f"  subsystem  = 0x{out[a+0x20]:02x}{out[a+0x21]:02x}")
    print(f"  PSID       = {bytes(out[a+0x24:a+0x24+14]).decode('latin1')}")
    print(f"  lcl[0]     = 0x{out[f+0x30b]:02x}  lcl[1] = 0x{out[f+0x317]:02x}  (fb 00 = 1p 100G+56G)")
    print(f"  PCIe width = 0x{out[h+0x8b]:02x} (0x09 = x16)")
    return bad == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-b', '--base', required=True, help="база C (12_28_4706 MCX456A dual-port)")
    ap.add_argument('-a', '--ref', required=True, help="справочник A (12_28_2302 MCX455A single-port)")
    ap.add_argument('-o', '--output')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--check', action='store_true')
    a = ap.parse_args()
    base = open(a.base, 'rb').read()
    ref = open(a.ref, 'rb').read()
    print(f"== base(C): {a.base.split('/')[-1]} md5 {hashlib.md5(base).hexdigest()}")
    print(f"== ref (A): {a.ref.split('/')[-1]} md5 {hashlib.md5(ref).hexdigest()}")
    if a.check:
        check_all_crc(base, "base"); return
    if check_all_crc(base, "base") != 0:
        sys.exit("CRC-модель не верифицирована на базе — abort")
    out = build(base, ref, a.dry_run)
    if a.dry_run:
        return
    ok = verify(out)
    if not a.output:
        sys.exit("нужен -o")
    open(a.output, 'wb').write(out)
    print(f"== записал: {a.output} ({len(out)} B, md5 {hashlib.md5(out).hexdigest()})")
    if not ok:
        sys.exit("верификация НЕ пройдена")
    print("== ГОТОВО: CRC OK, поля на месте. mstflint -i <out> q")


if __name__ == '__main__':
    main()
