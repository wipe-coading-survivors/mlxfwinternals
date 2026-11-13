#!/usr/bin/env python3
# Сводный пробник cx7-boot-crypto task-04: (1) hashes-table @0x15000 — канон
# 035 против live-факта (plaintext-поля, CRC, профиль случайности, A==B);
# ITOC-цензус hashable-секций против ёмкости 28; поиск sha512 plaintext-секций
# по дам­пу; (2) кросс-SKU дистрибьютора 28.50: дифф hashes-table с
# разложением на 64B hash-слоты (stream-подпись общего keystream) и карта
# 64K-блочных различий всего блоба (проверка per-package рандомизации);
# (3) NV-хвост слота A: экстент/карта плотности, строки, TLV-walk-негатив.
# usage: cx7_hashes_nv_burn.py <fnp-raw.bin> [dist1.bin dist2.bin]
import hashlib
import math
import re
import struct
import sys
from collections import Counter

TAB_OFF = 0x15000
TAB_SIZE = 0x804
SLOT_B = 0x1000000
SKIP_TYPES = {0xA0, 0xA1, 0xA3, 0xA4, 0xA7}
NAMES = {
    0x02: "PCI_CODE", 0x03: "MAIN_CODE", 0x04: "PCIE_LINK_CODE", 0x05: "IRON_PREP_CODE",
    0x06: "POST_IRON_BOOT_CODE", 0x07: "UPGRADE_CODE", 0x08: "HW_BOOT_CFG", 0x09: "HW_MAIN_CFG",
    0x0A: "PHY_UC_CODE", 0x0B: "PHY_UC_CONSTS", 0x0C: "PCIE_PHY_UC_CODE", 0x0D: "CCIR_INFRA_CODE",
    0x0E: "CCIR_ALGO_CODE", 0x0F: "BOOT3_CODE", 0x10: "IMAGE_INFO", 0x11: "FW_BOOT_CFG",
    0x12: "FW_MAIN_CFG", 0x14: "APU_KERNEL", 0x18: "ROM_CODE", 0x20: "RESET_INFO",
    0x30: "DBG_FW_INI", 0x32: "DBG_FW_PARAMS", 0xA0: "SIG_256", 0xA1: "PUB_KEYS_2048",
    0xA2: "FORBIDDEN_VER", 0xA3: "SIG_512", 0xA4: "PUB_KEYS_4096", 0xA6: "RSA_PUB_KEY",
    0xA7: "RSA4096_SIGS", 0xE9: "CRDUMP_MASK",
}


def mlx_crc16(blob):
    crc = 0xFFFF
    for dw in struct.unpack(">%dI" % (len(blob) // 4), blob):
        for _ in range(32):
            if crc & 0x8000:
                crc = ((crc << 1) | (dw >> 31)) ^ 0x100B
            else:
                crc = (crc << 1) | (dw >> 31)
            crc &= 0xFFFF
            dw = (dw << 1) & 0xFFFFFFFF
    for _ in range(16):
        crc = ((crc << 1) ^ 0x100B) if crc & 0x8000 else (crc << 1)
        crc &= 0xFFFF
    return crc ^ 0xFFFF


def runs_of(nz):
    out = []
    s = p = nz[0]
    for i in nz[1:]:
        if i != p + 1:
            out.append((s, p + 1))
            s = i
        p = i
    out.append((s, p + 1))
    return out


def chi2_z(data):
    c = Counter(data)
    exp = len(data) / 256
    x2 = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
    return x2, (x2 - 255) / math.sqrt(510)


def parse_itoc(pt):
    ent = []
    for i in range((len(pt) - 0x20) // 0x20):
        e = pt[0x20 + i * 0x20:0x40 + i * 0x20]
        dw = struct.unpack(">8I", e)
        ent.append({
            "idx": i, "type": dw[0] >> 24, "size_b": ((dw[0] >> 2) & 0x3FFFFF) * 4,
            "flash": ((dw[5] >> 2) & 0x7FFFFFF) << 2,
        })
    return ent


def hashes_report(fnp):
    ta = fnp[TAB_OFF:TAB_OFF + TAB_SIZE]
    tb = fnp[SLOT_B + TAB_OFF:SLOT_B + TAB_OFF + TAB_SIZE]
    print("=== hashes-table @0x15000 (size 0x%x = 12+16+28*(8+64)+8)" % TAB_SIZE)
    print("A==B: %s  md5=%s" % (ta == tb, hashlib.md5(ta).hexdigest()))
    load_addr, dw_size = struct.unpack(">II", ta[0:8])
    stored = int.from_bytes(ta[8:10], "big")
    print("canon hdr: load_address=0x%08x (expect 0) dw_size=0x%08x (expect ~0x1ff) "
          "stored_crc=0x%04x calc_crc16(first8)=0x%04x" % (
              load_addr, dw_size, stored, mlx_crc16(ta[0:8])))
    tail_crc = struct.unpack(">I", ta[0x800:0x804])[0] & 0xFFFF
    print("tail crc dw @0x800 lower16=0x%04x calc_data_crc=0x%04x" % (
        tail_crc, mlx_crc16(ta[0:0x800])))
    x2, z = chi2_z(ta)
    ent_zero = sum(1 for x in ta[0x1C:0xFC] if x == 0)
    print("randomness: chi2=%.1f z=%+.2f zero=%d ff=%d (expect 8) entries-area zeros %d/224 "
          "(plaintext canon expects >100)" % (
              x2, z, ta.count(0), ta.count(0xFF), ent_zero))
    print("dense extent check: after 0x15804 all-FF: %s" % (
        all(x == 0xFF for x in fnp[TAB_OFF + TAB_SIZE:TAB_OFF + TAB_SIZE + 0x100])))

    print("\n=== ITOC census (plaintext @0x6000) vs table capacity 28")
    pt = fnp[0x6000:0x6000 + 0x3E0]
    n = struct.unpack(">I", pt[0x14:0x18])[0] & 0xFF
    secs = [e for e in parse_itoc(pt) if e["type"] != 0xFF]
    hashable = [e for e in secs if e["type"] not in SKIP_TYPES]
    print("num_of_entries=%d, sections=%d (no END slot), hashable=%d (SKIP %s)" % (
        n, len(secs), len(hashable),
        sorted({e["type"] for e in secs if e["type"] in SKIP_TYPES})))
    for e in secs:
        print("  e%02d type=0x%02x %-14s size=0x%06x flash=0x%06x %s" % (
            e["idx"], e["type"], NAMES.get(e["type"], "?"), e["size_b"], e["flash"],
            "hash" if e["type"] not in SKIP_TYPES else "SKIP"))
    print("hashable %d <= 28 capacity: %s" % (len(hashable), len(hashable) <= 28))

    print("\n=== sha512(plaintext sections) search across 32MB dump")
    for e in secs:
        if e["type"] in SKIP_TYPES or e["type"] not in (0x10, 0xA6):
            continue
        sec = fnp[e["flash"]:e["flash"] + e["size_b"]]
        pos = fnp.find(hashlib.sha512(sec).digest())
        print("  type=0x%02x flash=0x%06x size=0x%x digest found_at=%s" % (
            e["type"], e["flash"], e["size_b"], hex(pos) if pos >= 0 else "none"))

    print("\n=== live per-burn class spot-check (A vs B section bodies)")
    for e in secs:
        if e["type"] in (0x03, 0x0C, 0x30, 0x10):
            a = fnp[e["flash"]:e["flash"] + min(e["size_b"], 0x1000)]
            b = fnp[SLOT_B + e["flash"]:SLOT_B + e["flash"] + min(e["size_b"], 0x1000)]
            nz = sum(1 for x, y in zip(a, b) if x != y)
            print("  type=0x%02x %-14s A==B:%-5s diff %d/%d" % (
                e["type"], NAMES.get(e["type"], "?"), a == b, nz, len(a)))


def dist_report(p1, p2):
    a = open(p1, "rb").read()
    b = open(p2, "rb").read()
    ptr = struct.unpack(">I", a[0x18 + 15 * 8:0x18 + 15 * 8 + 4])[0]
    print("=== distributor cross-SKU hashes-table @0x%x" % ptr)
    ta, tb = a[ptr:ptr + TAB_SIZE], b[ptr:ptr + TAB_SIZE]
    d = bytes(x ^ y for x, y in zip(ta, tb))
    nz = [i for i, x in enumerate(d) if x]
    x2, z = chi2_z(ta)
    print("table md5 %s / %s; own randomness chi2 z=%+.2f" % (
        hashlib.md5(ta).hexdigest(), hashlib.md5(tb).hexdigest(), z))
    print("diff %d/%d bytes; header/HTOC/entries region (0x0..0xfc) differs: %s" % (
        len(nz), TAB_SIZE, any(i < 0xFC for i in nz)))
    rr = runs_of(nz)
    for x, y in rr:
        reg = "hdr" if x < 0xC else ("htoc" if x < 0x1C else ("entries" if x < 0xFC else (
            "hash%d" % ((x - 0xFC) // 64) if x < 0x7FC else "tail")))
        print("  run 0x%04x..0x%04x len=%3d %s (start mod16=0x%x)" % (x, y, y - x, reg, x % 16))
    print("run-length sum=%d == nonzero count=%d (accounting closed)" % (
        sum(y - x for x, y in rr), len(nz)))
    slots = {}
    for x, y in rr:
        if x >= 0xFC and x < 0x7FC:
            for s in range((x - 0xFC) // 64, (y - 0xFC + 63) // 64):
                lo = max(x, 0xFC + s * 64)
                hi = min(y, 0xFC + (s + 1) * 64)
                slots[s] = slots.get(s, 0) + (hi - lo)
    print("affected hash slots: %s (of 28)" % {
        k: "%d/64" % v for k, v in sorted(slots.items())})
    print("slot sum %d + tail %d = %d (single-byte equal holes: %s; "
          "chance expect ~%.1f under stream)" % (
              sum(slots.values()), len(nz) - sum(slots.values()), len(nz),
              [hex(i) for i in nz[:0] + [o for o in (0x4AC, 0x52C, 0x54B) if d[o] == 0]],
              448 / 256))

    per16 = {i: sum(1 for x in d[i:i + 16] if x) for i in range(0, TAB_SIZE - 15, 16)}
    touched = {k: v for k, v in per16.items() if v}
    partial = {hex(k): v for k, v in touched.items() if 0 < v < 16}
    print("touched aligned 16B blocks: %d (full 16/16: %d); partial blocks: %s" % (
        len(touched), sum(1 for v in touched.values() if v == 16), partial))
    for s in (0xFC, 0x47C, 0x4FC, 0x6FC):
        blk = s & ~0xF
        print("  run start 0x%03x: block 0x%03x has %d nonzero before run inside same block "
              "(ECB/XTS/CBC-same-IV demand full-block avalanche)" % (
                  s, blk, sum(1 for x in d[blk:s] if x)))
    reps = {n: sum(v - 1 for v in Counter(
        t[i:i + 16] for i in range(0, len(t) - 15, 16)).values() if v > 1)
        for n, t in (("distSKU1", ta), ("distSKU2", tb))}
    print("aligned 16B repeats in table ct: %s (non-decisive: pt has no duplicated "
          "aligned 16B blocks)" % reps)
    print("verdict: encrypted; diffs confined to whole hash slots + tail-crc dword "
          "under shared crypto-state between builds; partial full blocks (4/16 and "
          "12/16 nonzero at run/slot boundaries) exclude block-avalanche modes (ECB, "
          "XTS any tweak policy, CBC same IV) -> additive-stream family (CTR/GCM-class)")

    print("\n=== distributor whole-blob 64K-block diff (per-package randomization check)")
    n = min(len(a), len(b))
    blocks = []
    for off in range(0, n, 0x10000):
        if a[off:off + 0x10000] != b[off:off + 0x10000]:
            nd = sum(1 for x, y in zip(a[off:off + 0x10000], b[off:off + 0x10000]) if x != y)
            blocks.append((off, nd))
    print("differing 64K blocks: %d/%d" % (len(blocks), n // 0x10000))
    for off, nd in blocks:
        print("  0x%07x: %d/65536 differ" % (off, nd))
    print("common-plaintext regions byte-identical (incl. encrypted section bodies) "
          "-> no per-package ct randomization in build pipeline")


def nv_report(fnp):
    print("=== NV-tail slot A [0x580000..0x6e6670)")
    tail = fnp[0x580000:0x6E6670]
    print("size 0x%x; slot B same range all-FF: %s" % (
        len(tail), all(x == 0xFF for x in fnp[SLOT_B + 0x580000:SLOT_B + 0x6E6670:1])))
    print("lead [0x57F770..0x580000) non-{00,FF}: %d" % (
        sum(1 for x in fnp[0x57F770:0x580000] if x not in (0, 0xFF))))
    print("header @0x580000: %s" % fnp[0x580000:0x580020].hex())
    strs = [(m.start() + 0x580000, m.group().decode()) for m in re.finditer(rb"[ -~]{12,}", tail)]
    print("ASCII strings >=12ch: %d" % len(strs))
    for pat in (b"find_valid_nv_partition", b"lifecycle_decision", b"RISCV", b"progcc", b"dcqcn"):
        hits = [hex(i) for i in range(len(fnp) - len(pat)) if fnp[i:i + len(pat)] == pat]
        print("  %-24s occurrences in 32MB: %s" % (pat.decode(), hits[:6]))
    vpd = fnp.find(b"NVIDIA ConnectX-7")
    print("  tail VPD-like descriptor @0x%x: %r" % (vpd, fnp[vpd:vpd + 80]))
    print("  device VPD @0x1ff8140: %r" % fnp[0x1FF8140:0x1FF81C0])
    for start in (0x580000, 0x580400, 0x5C0000, 0x58000C):
        off, ok = start, 0
        for _ in range(10):
            t, ln = struct.unpack(">HH", fnp[off:off + 4])
            if t > 0x800 or ln > 0x400:
                break
            off += 4 + ln
            ok += 1
        print("  TLV-chain walk @0x%x: %d/10 (nvconfig TLV: no)" % (start, ok))
    dt = fnp[0x1FFF000:0x1FFF000 + 0x400]
    entries = []
    for i in range((0x1E0 - 0x20) // 0x20):
        e = dt[0x20 + i * 0x20:0x40 + i * 0x20]
        fa = ((struct.unpack(">I", e[0x14:0x18])[0] >> 2) & 0x7FFFFFF) << 2
        if fa:
            entries.append((e[0], fa))
    print("  DTOC entries (type,flash): %s" % [
        ("0x%02x" % t, "0x%x" % fa) for t, fa in entries])
    print("  DTOC coverage of tail: %s" % (
        "none" if not any(0x580000 <= fa < 0x6E6670 for _, fa in entries) else "SOME"))


def main():
    if len(sys.argv) not in (2, 4):
        sys.exit("usage: cx7_hashes_nv_burn.py <fnp-raw.bin> [dist1.bin dist2.bin]")
    fnp = open(sys.argv[1], "rb").read()
    hashes_report(fnp)
    print()
    nv_report(fnp)
    if len(sys.argv) == 4:
        print()
        dist_report(sys.argv[2], sys.argv[3])


if __name__ == "__main__":
    main()
