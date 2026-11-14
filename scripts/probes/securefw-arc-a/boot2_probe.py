#!/usr/bin/env python3
# Формат-идентификация boot2-региона @0x1000 (securefw-arc-a task-04,
# bounded-чек-лист (а)-(е) спеки §3 T4):
#   (а) parse_boot2      — Carmel-контейнер DW0/DW1, size=(4+DW1)*4,
#                          подрегионы header/body/trailer+CRC16
#                          (crc16_mlx = mstflint Crc16, poly 0x100b,
#                          покрытие DW0..trailer; CheckBoot2-совместимо);
#   (б) entropy_profile  — по подрегионам + тело по 4K/16B-окнам
#                          (структурная проба, НЕ классификатор);
#   (в) irisc_rate       — доля known-form слов канонного декодера
#                          scripts.irisc (fb-метод) vs random-контроль;
#   (г) comp_sweep       — таблица fb task-02 (zlib-raw/zlib/gzip/bz2/
#                          xz/lzma-alone + zstd CLI опционально) + lz4
#                          frame/legacy чистым Pythonом (no-dep ruling,
#                          чексуммы не верифицируются — xxh32 вне пробника);
#   (д) cross_skeleton   — заголовки/скелет против другого региона
#                          (CX-6Dx 22.50 ref: dw0-семейство, head-common,
#                          позиционный word-match);
#   (е) riscv/arm_profile — opcode-гистограммы уровня паттернов
#                          (RV32I major-op frac + RVC frac; T32-prefix,
#                          A32-cond, A64 op-гистограмма) vs random-контроль.
# Исчерпание чек-листа = стоп (Review Focus 4, bounded).
# usage: boot2_probe.py <a.bin> <b.bin> [--ref cx6dx.bin]
#       [--boot2-off 0x1000] [--json out.json]
import argparse
import bz2
import hashlib
import json
import lzma
import math
import os
import struct
import subprocess
import sys
import zlib
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.irisc import disasm

BOOT2_OFF = 0x1000
CARMEL_DW0 = (0x20400040, 0x00400040)
COMP_MIN_OUT = 0x400
SWEEP_SPAN = 65
ZSTD = "/usr/bin/zstd"
RV32I_MAJOR = {0x00, 0x03, 0x04, 0x05, 0x08, 0x0B, 0x0C, 0x18, 0x19,
               0x1B, 0x1C, 0x1D}


def crc16_mlx(data):
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


def parse_boot2(buf, off=BOOT2_OFF):
    out: dict = {"status": None, "err": "", "dw0": None, "dw1": None,
           "size": None, "body": None, "trailer_dw": None, "crc_dw": None,
           "crc_calc": None, "crc_ok": None, "family": None}
    if off + 8 > len(buf):
        out.update(status="no-window", err="no header window")
        return out
    dw0, dw1 = struct.unpack_from(">II", buf, off)
    out["dw0"], out["dw1"] = dw0, dw1
    if dw0 == 0xFFFFFFFF and dw1 == 0xFFFFFFFF:
        out.update(status="erased", err="erased window")
        return out
    size = (4 + dw1) * 4
    if off + size > len(buf):
        out.update(status="truncated",
                   err="size %#x overruns buffer" % size)
        return out
    region = buf[off:off + size]
    body = region[8:8 + dw1 * 4]
    trailer_dw = struct.unpack_from(">I", region, 8 + dw1 * 4)[0]
    crc_dw = struct.unpack_from(">I", region, 8 + dw1 * 4 + 4)[0]
    crc_calc = crc16_mlx(region[:8 + dw1 * 4 + 4])
    out.update(status="ok", size=size, body=body, trailer_dw=trailer_dw,
               crc_dw=crc_dw, crc_calc=crc_calc, crc_ok=crc_dw == crc_calc,
               family=dw0 in CARMEL_DW0)
    return out


def _shannon(data):
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def entropy_profile(data):
    per4k = [_shannon(data[i:i + 4096]) for i in range(0, len(data), 4096)]
    wins = [_shannon(data[i:i + 16]) for i in range(0, len(data) - 15, 16)]
    return {
        "whole": round(_shannon(data), 3),
        "per4k_min": round(min(per4k), 3) if per4k else None,
        "per4k_max": round(max(per4k), 3) if per4k else None,
        "per4k_blocks": len(per4k),
        "win16_min": round(min(wins), 3) if wins else None,
        "win16_max": round(max(wins), 3) if wins else None,
        "win16_avg": round(sum(wins) / len(wins), 3) if wins else None,
    }


def irisc_rate(data):
    n = len(data) // 4
    if not n:
        return {"words": 0, "known": 0, "frac": 0.0, "top": []}
    words = struct.unpack(">%dI" % n, data[:n * 4])
    known = 0
    census = {}
    for w in words:
        r = disasm(w, 0)
        key = r.split()[0].split(",")[0]
        census[key] = census.get(key, 0) + 1
        if not (r.startswith("op0x") or r.startswith("alu.0x")):
            known += 1
    top = sorted(census.items(), key=lambda kv: -kv[1])[:10]
    return {"words": n, "known": known,
            "frac": round(known / n, 4), "top": top}


def lz4_block_decompress(src, max_out=8 << 20):
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                if i >= n:
                    raise ValueError("truncated literal length")
                b = src[i]
                i += 1
                lit_len += b
                if b != 255:
                    break
        if i + lit_len > n:
            raise ValueError("truncated literals")
        out += src[i:i + lit_len]
        i += lit_len
        if i >= n:
            break
        if i + 2 > n:
            raise ValueError("truncated offset")
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0:
            raise ValueError("zero offset")
        match_len = token & 0xF
        if match_len == 15:
            while True:
                if i >= n:
                    raise ValueError("truncated match length")
                b = src[i]
                i += 1
                match_len += b
                if b != 255:
                    break
        match_len += 4
        if offset > len(out):
            raise ValueError("offset before start")
        if len(out) + match_len > max_out:
            raise ValueError("output too large")
        start = len(out) - offset
        for k in range(match_len):
            out.append(out[start + k])
    return bytes(out)


def lz4_frame_decompress(data, max_out=8 << 20):
    # LZ4 frame format spec: FLG bits 7-6 Version, 5 B.Indep (no field),
    # 4 B.Checksum (+4/block), 3 C.Size (+8 in header), 2 C.Checksum
    # (+4 after EndMark), 1 Reserved (must be 0), 0 DictID (+4 in
    # header, after Content Size). Checksum bytes are skipped, not
    # verified (xxh32 out of scope).
    if data[:4] != struct.pack("<I", 0x184D2204):
        raise ValueError("not an lz4 frame")
    if len(data) < 7:
        raise ValueError("short frame header")
    flg = data[4]
    if (flg >> 6) & 3 != 1:
        raise ValueError("bad frame version")
    if flg & 0x02:
        raise ValueError("reserved FLG bit set")
    pos = 7
    if flg & 0x08:
        pos += 8
    if flg & 0x01:
        pos += 4
    out = bytearray()
    while True:
        if pos + 4 > len(data):
            raise ValueError("truncated block size")
        bsize = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if bsize == 0:
            break
        uncompressed = bool(bsize & 0x80000000)
        bsize &= 0x7FFFFFFF
        if pos + bsize > len(data):
            raise ValueError("truncated block")
        blk = data[pos:pos + bsize]
        pos += bsize
        if uncompressed:
            out += blk
        else:
            out += lz4_block_decompress(blk, max_out)
        if flg & 0x10:
            pos += 4
        if len(out) > max_out:
            raise ValueError("output too large")
    if flg & 0x04:
        pos += 4
    return bytes(out)


def lz4_legacy_decompress(data, max_out=8 << 20):
    # Legacy format: magic (4B LE) then blocks of (u32 LE CSize, CData);
    # CSize high bit = uncompressed block; CSize 0 = end. No header
    # fields between magic and first block.
    if data[:4] != struct.pack("<I", 0x184C2102):
        raise ValueError("not lz4 legacy")
    pos = 4
    out = bytearray()
    while True:
        if pos + 4 > len(data):
            raise ValueError("truncated block size")
        bsize = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if bsize == 0:
            break
        uncompressed = bool(bsize & 0x80000000)
        bsize &= 0x7FFFFFFF
        if pos + bsize > len(data):
            raise ValueError("truncated block")
        blk = data[pos:pos + bsize]
        pos += bsize
        if uncompressed:
            out += blk
        else:
            out += lz4_block_decompress(blk, max_out)
        if len(out) > max_out:
            raise ValueError("output too large")
        if pos >= len(data):
            break
    return bytes(out)


_DECOMP = {
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
        out += _DECOMP[algo]().decompress(feed, 0x100000)
    except Exception as e:
        err = str(e)[:60]
    return len(out), bytes(out[:16]).hex(), err


def comp_sweep(blob):
    hits = []
    for off in range(min(SWEEP_SPAN, len(blob))):
        for algo in ("zlib-raw", "zlib", "gzip", "bz2", "xz", "lzma-alone"):
            n, head, err = _decomp(algo, blob[off:])
            if n >= COMP_MIN_OUT:
                hits.append((algo, off, n, head, err))
        for algo, fn in (("lz4-frame", lz4_frame_decompress),
                         ("lz4-legacy", lz4_legacy_decompress)):
            try:
                out = fn(blob[off:], 0x100000)
            except ValueError:
                continue
            if len(out) >= COMP_MIN_OUT:
                hits.append((algo, off, len(out), out[:16].hex(), None))
        if os.path.exists(ZSTD):
            try:
                p = subprocess.run([ZSTD, "-dc", "-q"], input=blob[off:],
                                   capture_output=True, timeout=60)
                if len(p.stdout) >= COMP_MIN_OUT:
                    hits.append(("zstd", off, len(p.stdout),
                                 p.stdout[:16].hex(),
                                 None if p.returncode == 0
                                 else "rc=%d" % p.returncode))
            except Exception:
                pass
    return hits


def riscv_profile(data):
    n = len(data) // 4
    if not n:
        return {"words": 0, "frac_major": 0.0, "rvc_frac": 0.0,
                "hist_top": []}
    words = struct.unpack_from("<%dI" % n, data)
    hist = {}
    ok = 0
    for w in words:
        op = (w >> 2) & 0x1F
        hist[op] = hist.get(op, 0) + 1
        if op in RV32I_MAJOR:
            ok += 1
    n2 = len(data) // 2
    hws = struct.unpack_from("<%dH" % n2, data)
    rvc = sum(1 for h in hws if h & 3)
    top = sorted(hist.items(), key=lambda kv: -kv[1])[:5]
    return {"words": n, "frac_major": round(ok / n, 4),
            "rvc_frac": round(rvc / n2, 4), "hist_top": top}


def arm_profile(data):
    n2 = len(data) // 2
    if not n2:
        return {"halfwords": 0, "t32_prefix_frac": 0.0, "a32_cond_frac": 0.0,
                "op_top": []}
    hws = struct.unpack_from("<%dH" % n2, data)
    t32 = sum(1 for h in hws if h >= 0xE800)
    n4 = len(data) // 4
    cond = 0
    op_hist = {}
    if n4:
        for w in struct.unpack_from("<%dI" % n4, data):
            if (w >> 28) != 0xF:
                cond += 1
            k = (w >> 24) & 0xFF
            op_hist[k] = op_hist.get(k, 0) + 1
    top = sorted(op_hist.items(), key=lambda kv: -kv[1])[:5]
    return {"halfwords": n2,
            "t32_prefix_frac": round(t32 / n2, 4),
            "a32_cond_frac": round(cond / n4, 4) if n4 else None,
            "op_top": top}


def cross_skeleton(pa, pb):
    out: dict = {"dw0_eq": None, "dw1_a": None, "dw1_b": None,
           "head_common": None, "word_match_frac": None,
           "md5_a": None, "md5_b": None}
    if pa["status"] != "ok" or pb["status"] != "ok":
        return out
    wa = [pa["dw0"], pa["dw1"]]
    wb = [pb["dw0"], pb["dw1"]]
    for head_words, p in ((wa, pa), (wb, pb)):
        if p["body"]:
            take = p["body"][:24]
            head_words.extend(struct.unpack(">%dI" % (len(take) // 4),
                                            take))
    out["dw0_eq"] = pa["dw0"] == pb["dw0"]
    out["dw1_a"], out["dw1_b"] = pa["dw1"], pb["dw1"]
    out["head_common"] = sum(1 for x, y in zip(wa, wb) if x == y)
    ba, bb = pa["body"], pb["body"]
    out["md5_a"] = hashlib.md5(ba).hexdigest()
    out["md5_b"] = hashlib.md5(bb).hexdigest()
    n = min(len(ba), len(bb)) // 4
    if n:
        vwa = struct.unpack(">%dI" % n, ba[:n * 4])
        vwb = struct.unpack(">%dI" % n, bb[:n * 4])
        out["word_match_frac"] = round(
            sum(1 for x, y in zip(vwa, vwb) if x == y) / n, 4)
    return out


def probe_report(buf, off=BOOT2_OFF, rnd=None):
    if rnd is None:
        rnd = os.urandom
    p = parse_boot2(buf, off)
    rep: dict = {"parse": {k: v for k, v in p.items() if k != "body"}}
    if p["status"] != "ok":
        return rep
    body = p["body"]
    rep["entropy"] = {
        "body": entropy_profile(body),
        "header": entropy_profile(buf[off:off + 8]),
        "trailer": entropy_profile(buf[off + p["size"] - 8:
                                    off + p["size"]]),
    }
    rep["irisc"] = irisc_rate(body)
    rep["irisc_random"] = irisc_rate(rnd(len(body)))
    rep["compress"] = comp_sweep(body)
    rep["riscv"] = riscv_profile(body)
    rep["riscv_random"] = riscv_profile(rnd(0x1000))
    rep["arm"] = arm_profile(body)
    rep["arm_random"] = arm_profile(rnd(0x1000))
    rep["md5_body"] = hashlib.md5(body).hexdigest()
    rep["body_head_words"] = ["%08x" % w for w in
                              struct.unpack(">8I", body[:32])]
    return rep


def build_report(path_a, path_b, ref_path=None, off=BOOT2_OFF, rnd=None):
    buf_a = Path(path_a).read_bytes()
    buf_b = Path(path_b).read_bytes()
    pa, pb = parse_boot2(buf_a, off), parse_boot2(buf_b, off)
    rep = {
        "a": {"path": str(path_a), **probe_report(buf_a, off, rnd=rnd)},
        "b": {"path": str(path_b), **probe_report(buf_b, off, rnd=rnd)},
        "cross_ab": cross_skeleton(pa, pb),
        "cross_ref": None,
        "ref": None,
    }
    if ref_path:
        buf_r = Path(ref_path).read_bytes()
        pr = parse_boot2(buf_r, off)
        rep["ref"] = {"path": str(ref_path),
                      **probe_report(buf_r, off, rnd=rnd)}
        rep["cross_ref"] = cross_skeleton(pa, pr)
    return rep


def _entropy_line(tag, prof):
    if not prof or prof.get("whole") is None:
        return "%s: n/a" % tag
    return ("%s: whole=%.3f per4k=%.2f..%.2f(%d) "
            "win16=%.2f..%.2f(avg %.2f)" % (
                tag, prof["whole"], prof["per4k_min"], prof["per4k_max"],
                prof["per4k_blocks"], prof["win16_min"] or 0,
                prof["win16_max"] or 0, prof["win16_avg"] or 0))


def _probe_lines(tag, item):
    lines = ["== %s (%s)" % (tag, item["path"])]
    p = item["parse"]
    lines.append("  parse: status=%s dw0=%s dw1=%s size=%s trailer=%s "
                 "crc_ok=%s family=%s" % (
                     p["status"],
                     "0x%08x" % p["dw0"] if p["dw0"] is not None else "-",
                     "0x%x" % p["dw1"] if p["dw1"] is not None else "-",
                     "0x%x" % p["size"] if p["size"] is not None else "-",
                     "0x%08x" % p["trailer_dw"]
                     if p["trailer_dw"] is not None else "-",
                     p["crc_ok"], p["family"]))
    if p["status"] != "ok":
        return lines
    e = item["entropy"]
    lines.append("  " + _entropy_line("entropy body ", e["body"]))
    lines.append("  " + _entropy_line("entropy head ", e["header"]))
    lines.append("  " + _entropy_line("entropy tail ", e["trailer"]))
    ir, irc = item["irisc"], item["irisc_random"]
    lines.append("  iRISC known-form: %d/%d = %.1f%%  "
                 "(random control %.1f%%)  top: %s" % (
                     ir["known"], ir["words"], 100 * ir["frac"],
                     100 * irc["frac"],
                     ", ".join("%s:%d" % kv for kv in ir["top"][:5])))
    hits = item["compress"]
    lines.append("  compress hits >=%#x @0..64: %s" % (
        COMP_MIN_OUT, hits if hits else "none"))
    rv, rvc = item["riscv"], item["riscv_random"]
    lines.append("  RISC-V: frac_major=%.3f (rand %.3f) rvc=%.3f  "
                 "hist: %s" % (
                     rv["frac_major"], rvc["frac_major"], rv["rvc_frac"],
                     ", ".join("0x%02x:%d" % (k, v)
                               for k, v in rv["hist_top"][:5])))
    ar, arc = item["arm"], item["arm_random"]
    lines.append("  ARM: t32=%.3f (rand %.3f) a32cond=%.3f (rand %.3f)  "
                 "op_top: %s" % (
                     ar["t32_prefix_frac"], arc["t32_prefix_frac"],
                     ar["a32_cond_frac"], arc["a32_cond_frac"],
                     ", ".join("0x%02x:%d" % (k, v)
                               for k, v in ar["op_top"][:5])))
    return lines


def _cross_lines(tag, sk):
    if sk is None or sk["dw0_eq"] is None:
        return ["== %s: n/a" % tag]
    return ["== %s: dw0_eq=%s dw1=%s/%s head_common=%s "
            "word_match=%.1f%% md5=%s..%s" % (
                tag, sk["dw0_eq"],
                "0x%x" % sk["dw1_a"], "0x%x" % sk["dw1_b"],
                sk["head_common"], 100 * (sk["word_match_frac"] or 0),
                sk["md5_a"][:8], sk["md5_b"][:8])]


def print_report(rep):
    for line in _probe_lines("A (0751)", rep["a"]):
        print(line)
    for line in _probe_lines("B (0800)", rep["b"]):
        print(line)
    if rep["ref"]:
        for line in _probe_lines("REF (cx6dx 22.50)", rep["ref"]):
            print(line)
    for line in _cross_lines("cross A<->B", rep["cross_ab"]):
        print(line)
    for line in _cross_lines("cross A<->REF", rep["cross_ref"]):
        print(line)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="boot2 format-identification probe (bounded (а)-(е))")
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--ref", default=None,
                    help="reference image with boot2 @off (cx6dx 22.50)")
    ap.add_argument("--boot2-off", type=lambda x: int(x, 0),
                    default=BOOT2_OFF)
    ap.add_argument("--json", metavar="OUT", default=None)
    args = ap.parse_args(argv)
    rep = build_report(args.a, args.b, ref_path=args.ref,
                       off=args.boot2_off)
    print_report(rep)
    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rep, indent=1) + "\n")
        print("\njson -> %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
