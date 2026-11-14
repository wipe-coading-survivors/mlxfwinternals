#!/usr/bin/env python3
# Provenance probe (securefw-arc-a task-05 review fix): committed code for
# the two data-driven exclusions of the boot_record task journal:
# 1) trailer integrity-field sweep — the boot_record trailer word (last
#    nonzero BE-DW of [0x100,0x500)) against a CRC16-family sweep over
#    three spans (body / incl_trailer / trailer_zeroed);
# 2) hashes-table slot probe — SHA-512 over raw flash bytes of each
#    section vs its hashes-table slot (28.33 pair, plaintext map @0x7000),
#    under BOTH slot decodings (ht-relative and ht+0x100-relative).
# Verdicts these reproduce (journal task-05 §0 / «Исследовано и
# исключено» / §7-§8): sweep = 0 hits on A/B/CX-6/CX-5; slot probe =
# 0 matches on all 24 hashable sections of both images, both bases
# (committed slow test test_real_exclusions_reproduced pins both).
# Limitation: reflected CRC16 variants (x25/kermit/usb) not swept.
# usage: bootrec_trailer_probe.py <img.bin> [more.bin ...] [--json out]
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

REC_OFF = 0x100
TOOLS_OFF = 0x500
HT_OFF_DEFAULT = 0x7000  # hashes_table_ptr (HW-ptr[15]) on the 28.33 pair
HT_HEADER_END = 0x100


def crc16_mlx(data):
    """mstflint Crc16 (poly 0x100b, init 0xffff, MSB-first, finish =
    16 zero bits + xor 0xffff) — same algorithm as boot2_probe.crc16_mlx
    (golden-tested there; golden pins duplicated in this probe's tests)."""
    crc = 0xFFFF

    def feed(bit):
        nonlocal crc
        if crc & 0x8000:
            crc = ((crc << 1) | bit) ^ 0x100B
        else:
            crc = (crc << 1) | bit
        crc &= 0xFFFF

    for b in data:
        for i in range(7, -1, -1):
            feed((b >> i) & 1)
    for _ in range(16):
        if crc & 0x8000:
            crc = ((crc << 1) ^ 0x100B) & 0xFFFF
        else:
            crc = (crc << 1) & 0xFFFF
    return crc ^ 0xFFFF


def crc16_plain(data, poly=0x1021, init=0xFFFF, reflected=False):
    """CRC16 without xorout; MSB-first by default, or LSB-first with
    reversed poly when reflected=True (true ARC/MODBUS)."""
    crc = init
    for b in data:
        if reflected:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        else:
            crc ^= b << 8
            for _ in range(8):
                crc = ((crc << 1) ^ poly) if crc & 0x8000 else (crc << 1)
                crc &= 0xFFFF
    return crc


def fletcher16(data):
    a = b = 0
    for x in data:
        a = (a + x) % 255
        b = (b + a) % 255
    return (b << 8) | a


VARIANTS = (
    ("mlx-100b", crc16_mlx),
    ("ccitt-false", lambda d: crc16_plain(d, poly=0x1021, init=0xFFFF)),
    ("xmodem", lambda d: crc16_plain(d, poly=0x1021, init=0x0000)),
    ("arc", lambda d: crc16_plain(d, poly=0xA001, init=0x0000,
                                  reflected=True)),
    ("modbus", lambda d: crc16_plain(d, poly=0xA001, init=0xFFFF,
                                     reflected=True)),
    ("fletcher16", fletcher16),
)


def _last_nonzero_word(region):
    n = len(region) // 4
    ws = struct.unpack(">%dI" % n, region[:n * 4])
    for i in range(n - 1, -1, -1):
        if ws[i] not in (0, 0xFFFFFFFF):
            return 4 * i, ws[i]
    return None, None


def trailer_sweep(region, trailer_off=None):
    """Match the trailer word against the CRC16-family sweep over three
    spans; returns hits [{variant, span}] (empty == excluded)."""
    if trailer_off is None:
        trailer_off, _value = _last_nonzero_word(region)
        if trailer_off is None:
            raise ValueError("no nonzero word in region")
    n = len(region) // 4
    ws = struct.unpack(">%dI" % n, region[:n * 4])
    trailer_value = ws[trailer_off // 4]
    spans = {
        "body": region[:trailer_off],
        "incl_trailer": region[:trailer_off + 4],
        "trailer_zeroed": region[:trailer_off] + b"\x00\x00\x00\x00",
    }
    hits = []
    for span_name, data in spans.items():
        for name, fn in VARIANTS:
            if fn(data) == trailer_value:
                hits.append({"variant": name, "span": span_name})
    return {
        "trailer_off": trailer_off,
        "trailer_value": trailer_value,
        "spans": {k: len(v) for k, v in spans.items()},
        "variants": [name for name, _fn in VARIANTS],
        "hits": hits,
    }


def parse_slot_map(buf, ht_off=HT_OFF_DEFAULT, header_end=HT_HEADER_END):
    """Hashes-table header map: (section_id<<16 | slot_offset) entries at
    8-byte stride (observed pair layout: entries from +0x1c); zero and
    0x..FFFF fill words skipped; scan stops before the header's own tag
    word at header_end-4. Slot offsets decoded as ht-relative (primary);
    NOTE: neither ht-relative nor (ht+0x100)-relative decoding is fully
    self-consistent on the observed header (first entry 0xf0 lands in
    the header vs last slot overshoots the 0x804 extent) — exact slot
    addressing open; the SHA-512 exclusion was verified under BOTH
    bases by the committed slow test (test_real_exclusions_reproduced:
    0 matches, all 24 hashable sections, both slot_base values).
    Returns {section_id: absolute slot off (ht-relative)}."""
    out = {}
    for off in range(0x1C, header_end - 4, 8):
        w = struct.unpack_from(">I", buf, ht_off + off)[0]
        sid, soff = (w >> 16) & 0xFF, w & 0xFFFF
        if sid == 0 or soff == 0xFFFF or w == 0:
            continue
        out[sid] = ht_off + soff
    return out


def sha512_slot_check(buf, sections, ht_off=HT_OFF_DEFAULT, slot_base=0):
    """SHA-512 over raw flash bytes of each section vs its slot.
    sections: {type: (addr, size)}. slot_base shifts the decoded slot
    address: 0 = ht-relative, 0x100 = (ht+0x100)-relative decoding.
    Returns {checked, match, miss, slot_base}."""
    slot_map = parse_slot_map(buf, ht_off=ht_off)
    match, miss = [], []
    for typ, (addr, size) in sorted(sections.items()):
        if typ not in slot_map:
            continue
        calc = hashlib.sha512(buf[addr:addr + size]).digest()
        slot_abs = slot_map[typ] + slot_base
        slot = buf[slot_abs:slot_abs + 64]
        (match if calc == slot else miss).append(typ)
    return {"checked": len(match) + len(miss), "match": match,
            "miss": miss, "slot_base": slot_base}


def sections_from_itoc(buf):
    import mlxfwutil as U
    img = U.Image(buf)
    return {e.type: (e.addr, e.size) for e in img.entries("ITOC")
            if e.type != 0xFF}


def hashes_table_ptr(buf):
    """HW-ptr[15] (hashes_table_pointer, Carmel order) — 0/FF = invalid
    (V1 images: the 0x7000 window is not a hashes table there)."""
    w = struct.unpack_from(">I", buf, 0x18 + 15 * 8)[0]
    return None if w in (0, 0xFFFFFFFF) else w


def probe_image(path):
    buf = Path(path).read_bytes()
    region = buf[REC_OFF:TOOLS_OFF]
    sweep = trailer_sweep(region)
    slots = None
    ht = hashes_table_ptr(buf)
    if ht is not None:
        slot_map = parse_slot_map(buf, ht_off=ht)
        if slot_map:
            sections = sections_from_itoc(buf)
            slots = [sha512_slot_check(buf, sections, ht_off=ht,
                                       slot_base=sb)
                     for sb in (0, 0x100)]
    return {
        "path": Path(path).name,
        "trailer_sweep": sweep,
        "hashes_table_ptr": ht,
        "hash_slots": slots,
        "slot_map_size": (len(parse_slot_map(buf, ht_off=ht))
                          if ht is not None else 0),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="boot_record trailer + hash-slot exclusion probes")
    ap.add_argument("images", nargs="+")
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args(argv)
    report = [probe_image(p) for p in args.images]
    for r in report:
        sw = r["trailer_sweep"]
        print("== %s ==" % r["path"])
        print("  trailer @+0x%x = 0x%08x  sweep hits: %s" % (
            sw["trailer_off"], sw["trailer_value"],
            sw["hits"] if sw["hits"] else "NONE (excluded)"))
        if r["hash_slots"] is not None:
            for hs in r["hash_slots"]:
                print("  hashes-table @0x%x slot_base=+0x%x: checked=%d "
                      "match=%s miss=%s" % (
                          r["hashes_table_ptr"], hs["slot_base"],
                          hs["checked"], hs["match"], hs["miss"]))
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
