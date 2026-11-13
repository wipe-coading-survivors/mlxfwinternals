#!/usr/bin/env python3
# Сводный формат-пробник boot2-подобных блобов (cx7-boot-crypto task-02).
# Для каждого блоба печатает: энтропийный профиль (целая, по 4K, 16B-окна),
# скан магиков стримов (0..64 и весь блоб), sweep-декомпрессию
# zlib/raw/gzip/bz2/xz/lzma-alone (+zstd CLI, lz4 недоступен без модуля),
# скан крипто-констант (AES/SHA/CRC/GHASH/ChaCha), period-XOR 1..64,
# равномерность байтов/повторы 16B/поля размера, iRISC-метрику слов
# (доля известных форм канонного декодера scripts.irisc + census).
# Без внешних зависимостей кроме /usr/bin/zstd (опционально).
# usage: python3 scripts/probes/cx7_boot2_probe.py <blob.bin> [blob2 ...]
import bz2
import lzma
import math
import os
import struct
import subprocess
import sys
import zlib
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from scripts.irisc import disasm

AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
SHA256_K12 = struct.pack(">12I", *[
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3])
SHA512_K3 = struct.pack(">3Q", 0x428a2f98d728ae22, 0x7137449123ef65cd,
                        0xb5c0fbcfec4d3b2f)
CONSTS = [
    ("AES-SBOX-256B", AES_SBOX),
    ("AES-SBOX-16B", AES_SBOX[:16]),
    ("AES-INV-SBOX-16B", bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    ("AES-Te0-16B", struct.pack(">4I", 0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d)),
    ("SHA256-K0-11", SHA256_K12),
    ("SHA256-K0-3", SHA256_K12[:16]),
    ("SHA512-K0-2", SHA512_K3),
    ("CRC32-poly-BE", struct.pack(">I", 0x04C11DB7)),
    ("CRC32-tab0-LE", struct.pack("<I", 0xEDB88320)),
    ("GHASH-e1", bytes.fromhex("e100000000000000")),
    ("ChaCha-expa", b"expand 32-byte k"),
    ("Carmel-boot2-DW0", struct.pack(">I", 0x20400040)),
    ("MTFW", b"MTFW"),
]
MAGICS = [
    ("ELF", b"\x7fELF"), ("gzip2B", b"\x1f\x8b"), ("xz", b"\xfd7zXZ\x00"),
    ("zstd", b"\x28\xb5\x2f\xfd"), ("lz4", b"\x04\x22\x4d\x18"),
    ("lzma-alone", b"\x5d\x00\x00"), ("bzip2", b"BZh"), ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("zlib-cfg", b"\x78\x9c"), ("zlib-cfg", b"\x78\xda"), ("zlib-cfg", b"\x78\x01"),
]
ZSTD = "/usr/bin/zstd"
COMP_MIN_OUT = 0x400
XOR_PERIOD_MAX = 64


def shannon(data):
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def report(path):
    blob = open(path, "rb").read()
    print("=== %s (%d B)" % (os.path.basename(path), len(blob)))
    print("entropy whole=%.3f  per-4K: %s" % (
        shannon(blob), " ".join("%.2f" % shannon(blob[i:i + 4096])
                                for i in range(0, len(blob), 4096))))
    wins = [shannon(blob[i:i + 16]) for i in range(0, len(blob) - 15, 16)]
    print("16B-window entropy: min=%.2f max=%.2f avg=%.2f" % (
        min(wins), max(wins), sum(wins) / len(wins)))
    print("magics 0..64: %s" % (magic_head(blob) or "none"))
    print("magics anywhere (<=5/class): %s" % (magic_anywhere(blob) or "none"))
    print("compression hits >=%#xB @0..64: %s" % (COMP_MIN_OUT, comp_sweep(blob) or "none"))
    print("const-signature hits: %s" % (const_scan(blob) or "none"))
    print("period-XOR top3 (frac,period,xorval): %s" % [
        (round(f, 4), p, hex(v)) for f, p, v in period_xor(blob)])
    c = Counter(blob)
    exp = len(blob) / 256
    x2 = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
    print("chi2-uniform: %.1f (z=%+.2f)" % (x2, (x2 - 255) / math.sqrt(510)))
    blocks = Counter(blob[i:i + 16] for i in range(0, len(blob) - 15, 16))
    print("16B aligned repeats: %d" % sum(v - 1 for v in blocks.values() if v > 1))
    print("size-field hits @0..256: %s" % (size_fields(blob) or "none"))
    k, n, top = irisc_metric(blob)
    print("iRISC known-form: %d/%d = %.1f%%  top: %s" % (k, n, 100.0 * k / n, top))
    head = "; ".join(disasm(w, i * 4) for i, w in enumerate(
        struct.unpack(">%dI" % min(6, len(blob) // 4), blob[:min(24, len(blob))])))
    print("head words: %s" % head)
    print()


def magic_head(blob, span=65):
    hits = []
    for name, magic in MAGICS:
        for off in range(min(span, len(blob))):
            if blob[off:off + len(magic)] == magic:
                hits.append((name, off))
    return hits


def magic_anywhere(blob):
    hits = []
    for name, magic in MAGICS:
        i, cnt = blob.find(magic), 0
        while i != -1 and cnt < 5:
            hits.append((name, i))
            cnt += 1
            i = blob.find(magic, i + 1)
    return hits


DECOMP = {
    "zlib-raw": lambda: zlib.decompressobj(-15),
    "zlib": lambda: zlib.decompressobj(15),
    "gzip": lambda: zlib.decompressobj(31),
    "bz2": bz2.BZ2Decompressor,
    "xz": lambda: lzma.LZMADecompressor(format=lzma.FORMAT_XZ),
    "lzma-alone": lambda: lzma.LZMADecompressor(format=lzma.FORMAT_ALONE),
}


def _decomp(algo, feed):
    out = bytearray()
    err = None
    try:
        out += DECOMP[algo]().decompress(feed, 0x100000)
    except Exception as e:
        err = str(e)[:60]
    return len(out), bytes(out[:16]).hex(), err


def comp_sweep(blob):
    hits = []
    for off in range(min(65, len(blob))):
        for algo in ("zlib-raw", "zlib", "gzip", "bz2", "xz", "lzma-alone"):
            n, head, err = _decomp(algo, blob[off:])
            if n >= COMP_MIN_OUT:
                hits.append((algo, off, n, head, err))
        if os.path.exists(ZSTD):
            try:
                p = subprocess.run([ZSTD, "-dc", "-q"], input=blob[off:],
                                   capture_output=True, timeout=60)
                if len(p.stdout) >= COMP_MIN_OUT:
                    hits.append(("zstd", off, len(p.stdout), p.stdout[:16].hex(),
                                 None if p.returncode == 0 else "rc=%d" % p.returncode))
            except Exception as e:
                pass
    return hits


def const_scan(blob):
    hits = []
    for name, pat in CONSTS:
        i = blob.find(pat)
        while i != -1:
            hits.append((name, i))
            i = blob.find(pat, i + 1)
    return hits


def period_xor(blob):
    best = []
    for p in range(1, XOR_PERIOD_MAX + 1):
        c = Counter(blob[i] ^ blob[i + p] for i in range(len(blob) - p))
        val, cnt = c.most_common(1)[0]
        best.append((cnt / (len(blob) - p), p, val))
    best.sort(reverse=True)
    return best[:3]


def size_fields(blob):
    hits = []
    n = len(blob)
    for off in range(0, min(256, len(blob) - 3), 4):
        for fmt, tag in ((">I", "BE"), ("<I", "LE")):
            v = struct.unpack_from(fmt, blob, off)[0]
            if abs(v - n) <= 0x100 or abs(v - n * 8) <= 0x400:
                hits.append((off, tag, hex(v)))
    return hits


def irisc_metric(blob):
    n = len(blob) // 4
    words = struct.unpack(">%dI" % n, blob[:n * 4])
    known = 0
    census = {}
    for w in words:
        r = disasm(w, 0)
        key = r.split()[0].split(",")[0]
        census[key] = census.get(key, 0) + 1
        if not (r.startswith("op0x") or r.startswith("alu.0x")):
            known += 1
    return known, n, sorted(census.items(), key=lambda kv: -kv[1])[:10]


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: cx7_boot2_probe.py <blob.bin> [...]")
    for path in sys.argv[1:]:
        report(path)


if __name__ == "__main__":
    main()
