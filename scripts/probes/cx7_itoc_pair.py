#!/usr/bin/env python3
# Сводный пробник золотой тест-пары ITOC (cx7-boot-crypto task-03):
# plaintext-ITOC @0x6000 (0x3E0) против encrypted-TOC @0x16000, оба слота
# FNP-дампа. Печатает: канон-проверки (pt A==B, ct A!=B, md5), карту
# per-burn различий ctA^ctB (runs, per-16B-block счётчики, нулевые позиции,
# периодичность mod 12/16), keystream-статистику ct^pt, парсер plaintext-ITOC
# (BE-семантика полей по image_layout_itoc_entry), карту нулевых слов pt,
# ECB/повтор-дискриминаторы, скан значений gcm_iv_delta в ct/d/ks и
# (опционально, для двух дистрибьюторов) кросс-SKU карту байт-локальных
# различий encrypted-TOC с разложением на поля ITOC-entries.
# usage: python3 scripts/probes/cx7_itoc_pair.py <fnp-raw.bin> [dist1.bin dist2.bin]
import hashlib
import math
import struct
import sys
from collections import Counter

PT_SIZE = 0x3E0
SLOT = {"ptA": 0x6000, "ctA": 0x16000, "ptB": 0x1006000, "ctB": 0x1016000}
DELTA = 0xC52923E2


def shannon(data):
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))


def runs_of(nz, step=1):
    out = []
    s = nz[0]
    p = nz[0]
    for i in nz[1:]:
        if i != p + step:
            out.append((s, p + step))
            s = i
        p = i
    out.append((s, p + step))
    return out


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


def chi2_z(data):
    c = Counter(data)
    exp = len(data) / 256
    x2 = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
    return x2, (x2 - 255) / math.sqrt(510)


def parse_itoc(pt):
    ent = []
    for i in range((len(pt) - 0x20) // 0x20):
        e = pt[0x20 + i * 0x20:0x40 + i * 0x20]
        dw = struct.unpack(">7I", e[:0x1C]) + (struct.unpack(">I", e[0x1C:0x20])[0],)
        ent.append({
            "idx": i, "type": dw[0] >> 24, "size_dw": (dw[0] >> 2) & 0x3FFFFF,
            "param0": dw[1] & 0x3FFFFFFF, "cache_line_crc": (dw[1] >> 30) & 1,
            "zipped": (dw[1] >> 31) & 1, "param1": dw[2],
            "version": dw[4] & 0xFFFF, "flash_addr": (dw[5] >> 2) & 0x7FFFFFF,
            "section_crc": dw[6] & 0xFFFF, "crc_type": (dw[6] >> 16) & 7,
            "encrypted": dw[6] >> 31, "itoc_entry_crc": dw[7] & 0xFFFF,
        })
    return ent


FIELD_OF_BYTE = {}
for off, name in ((0x00, "type"), (0x01, "size"), (0x02, "size"), (0x03, "size"),
                  (0x04, "param0"), (0x08, "param1"), (0x10, "version"),
                  (0x14, "rsvd"), (0x16, "flash_addr"), (0x17, "flash_addr"),
                  (0x18, "sec_crc_hi"), (0x19, "sec_crc"), (0x1A, "sec_crc"),
                  (0x1B, "sec_crc"), (0x1C, "rsvd"), (0x1D, "rsvd"),
                  (0x1E, "itoc_crc"), (0x1F, "itoc_crc")):
    FIELD_OF_BYTE[off] = name


def live_report(fnp):
    b = {k: fnp[v:v + PT_SIZE] for k, v in SLOT.items()}
    print("=== golden pair extraction")
    for k in ("ptA", "ptB", "ctA", "ctB"):
        print("%s md5=%s head=%s" % (k, hashlib.md5(b[k]).hexdigest(), b[k][:16].hex()))
    print("canon: ptA==ptB %s | ctA==ctB %s | ctA==ptA %s" % (
        b["ptA"] == b["ptB"], b["ctA"] == b["ctB"], b["ctA"] == b["ptA"]))

    d = xor(b["ctA"], b["ctB"])
    ksA = xor(b["ctA"], b["ptA"])
    ksB = xor(b["ctB"], b["ptA"])
    nz = [i for i, x in enumerate(d) if x]
    print("\n=== ctA^ctB per-burn difference map")
    print("nonzero %d/%d, first 0x%x last 0x%x, zero bytes at %s (expect ~%.1f chance)" % (
        len(nz), len(d), nz[0], nz[-1], [hex(i) for i in range(len(d)) if d[i] == 0],
        len(d) / 256))
    print("runs: %s" % [(hex(a), hex(c)) for a, c in runs_of(nz)])
    per16 = [sum(1 for x in d[i:i + 16] if x) for i in range(0, len(d), 16)]
    print("per-16B-block diff bytes: min=%d max=%d blocks0=%d" % (
        min(per16), max(per16), sum(1 for x in per16 if x == 0)))
    for m in (12, 16):
        h = [sum(1 for i in range(len(d)) if d[i] == 0 and i % m == r) for r in range(m)]
        print("zero-count per residue mod %d: %s (flat expected)" % (m, h))
    x2, z = chi2_z(d)
    print("d byte chi2=%.1f z=%+.2f; 16B aligned repeats=%d" % (
        x2, z, sum(v - 1 for v in Counter(d[i:i + 16] for i in range(0, len(d), 16)).values() if v > 1)))
    print("ksA==ksB: %s; ksA^ksB==ctA^ctB: %s" % (ksA == ksB, xor(ksA, ksB) == d))
    for nm, ks in (("ksA", ksA), ("ksB", ksB)):
        x2, z = chi2_z(ks)
        reps = sum(v - 1 for v in Counter(ks[i:i + 16] for i in range(0, len(ks), 16)).values() if v > 1)
        print("%s nonzero=%d/%d chi2=%.1f z=%+.2f 16B repeats=%d" % (
            nm, sum(1 for x in ks if x), len(ks), x2, z, reps))

    print("\n=== plaintext ITOC parse (BE dword, value-bit semantics)")
    dw14 = struct.unpack(">I", b["ptA"][0x14:0x18])[0]
    hdr_crc = struct.unpack(">H", b["ptA"][0x1E:0x20])[0]
    print("num_of_entries@0x14=0x%x; header sigs: %s; hdr_crc=0x%04x calc=0x%04x %s" % (
        dw14 & 0xFF, b["ptA"][:0x10].hex(), hdr_crc,
        mlx_crc16(b["ptA"][:0x1C]), "OK" if hdr_crc == mlx_crc16(b["ptA"][:0x1C]) else "NG"))
    ecrc_ok = 0
    for e in parse_itoc(b["ptA"]):
        raw = b["ptA"][0x20 + e["idx"] * 0x20:0x40 + e["idx"] * 0x20]
        calc = mlx_crc16(raw[:0x1C])
        ecrc_ok += calc == e["itoc_entry_crc"]
        print("e%02d type=0x%02x size=0x%06x flash=0x%06x p0=0x%08x p1=0x%08x "
              "clc=%d enc=%d sec_crc=0x%04x e_crc=0x%04x calc=0x%04x %s" % (
                  e["idx"], e["type"], e["size_dw"] * 4, e["flash_addr"] << 2,
                  e["param0"], e["param1"], e["cache_line_crc"], e["encrypted"],
                  e["section_crc"], e["itoc_entry_crc"], calc,
                  "OK" if calc == e["itoc_entry_crc"] else "NG"))
    print("entry CRC self-check: %d/%d OK" % (ecrc_ok, len(parse_itoc(b["ptA"]))))
    zw = [i for i in range(0, len(b["ptA"]) - 3, 4) if b["ptA"][i:i + 4] == b"\0\0\0\0"]
    rr = [(hex(a), hex(c)) for a, c in runs_of(zw, 4) if c - a >= 8]
    print("pt zero-dword runs (>=8B): %s" % rr)
    tail_ff = 0
    for i in range(len(b["ptA"]) - 1, -1, -1):
        if b["ptA"][i] != 0xFF:
            tail_ff = len(b["ptA"]) - 1 - i
            break
    print("pt tail FF padding: %d B (record fully packed: %s)" % (
        tail_ff, tail_ff == 0))
    reps = {k: v for k, v in Counter(
        b["ptA"][i:i + 16] for i in range(0, len(b["ptA"]), 16)).items() if v > 1}
    print("pt aligned 16B repeats: %d -> ECB-in-record discriminator %s" % (
        len(reps), "INCONCLUSIVE (no repeated blocks)" if not reps else "usable"))
    hits = 0
    for blk in reps:
        for ct in (b["ctA"], b["ctB"]):
            var = Counter(ct[i:i + 16] for i in range(0, PT_SIZE, 16)
                          if b["ptA"][i:i + 16] == blk)
            hits += sum(v - 1 for v in var.values() if v > 1)
    print("ECB same-ct matches on repeats: %d" % hits)
    ct_reps = sum(v - 1 for v in Counter(
        b["ctA"][i:i + 16] for i in range(0, PT_SIZE, 16)).values() if v > 1)
    print("ctA aligned 16B repeats: %d; ct 'ITOC' magic: A=%d B=%d" % (
        ct_reps, b["ctA"].count(b"ITOC"), b["ctB"].count(b"ITOC")))

    print("\n=== gcm_iv_delta hypothesis checks (python3 arithmetic)")
    print("delta=0x%08x ^tocA=0x%08x +tocA=0x%08x +tocB=0x%08x -delta=0x%08x" % (
        DELTA, DELTA ^ 0x16000, (DELTA + 0x16000) & 0xFFFFFFFF,
        (DELTA + 0x1016000) & 0xFFFFFFFF, (-DELTA) & 0xFFFFFFFF))
    tgts = {DELTA, DELTA ^ 0xFFFFFFFF, (-DELTA) & 0xFFFFFFFF}
    found = []
    for nm, blob in (("ctA", b["ctA"]), ("ctB", b["ctB"]), ("d", d), ("ksA", ksA), ("ksB", ksB)):
        for i in range(0, PT_SIZE - 3):
            for fmt in (">I", "<I"):
                if struct.unpack_from(fmt, blob, i)[0] in tgts:
                    found.append((nm, hex(i), fmt))
    print("delta-value 4B occurrences in ct/d/ks (BE+LE, any align): %s" % (
        found if found else "none"))


def distributor_report(p1, p2):
    a = open(p1, "rb").read()
    b = open(p2, "rb").read()
    toc = struct.unpack(">I", a[0x18 + 2 * 8:0x18 + 2 * 8 + 4])[0]
    delta = struct.unpack(">I", a[0x18 + 14 * 8:0x18 + 14 * 8 + 4])[0]
    print("=== distributor cross-SKU encrypted-TOC (toc_ptr=0x%x, gcm_iv_delta=0x%08x)" % (
        toc, delta))
    ea, eb = a[toc:toc + 0x1000], b[toc:toc + 0x1000]
    last = max(i for i, x in enumerate(ea) if x != 0xFF)
    ea, eb = ea[:last + 1], eb[:last + 1]
    nz = [i for i in range(min(len(ea), len(eb))) if ea[i] != eb[i]]
    print("record dense extent: 0x%x B, identical-across-SKU bytes: %d/%d" % (
        last + 1, min(len(ea), len(eb)) - len(nz), last + 1))
    print("diff runs (record-relative):")
    for x, y in runs_of(nz):
        ereg = (x - 0x20) // 0x20 if x >= 0x20 else -1
        foff = (x - 0x20) % 0x20 if x >= 0x20 else x
        fld = FIELD_OF_BYTE.get(foff, "?")
        print("  0x%03x..0x%03x len=%d entry#%d+0x%02x field=%s %s -> %s" % (
            x, y, y - x, ereg, foff, fld, ea[x:y].hex(), eb[x:y].hex()))
    blk_confined = all((x % 16 == 0 and y % 16 == 0) for x, y in runs_of(nz))
    print("16B-block-confined: %s -> avalanche modes (CBC/XTS/ECB) %s" % (
        blk_confined, "CONSISTENT" if blk_confined else "REFUTED for build-time crypto"))
    print("xor of ct pair = pt-diff under stream model; byte-localized=%s" % (
        all(y - x <= 4 for x, y in runs_of(nz))))


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        sys.exit("usage: cx7_itoc_pair.py <fnp-raw.bin> [dist1.bin dist2.bin]")
    live_report(open(sys.argv[1], "rb").read())
    if len(sys.argv) == 4:
        print()
        distributor_report(sys.argv[2], sys.argv[3])


if __name__ == "__main__":
    main()
