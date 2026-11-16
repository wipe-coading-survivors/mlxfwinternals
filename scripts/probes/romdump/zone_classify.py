#!/usr/bin/env python3
"""romdump RD-B (Task 2): zone classification against flash byte-forms.

zone_classify.match_forms(zone_bytes, sources) -> report searches every
block-sized window of a dumped runtime zone in each candidate byte-form of
the flash content and reports matched windows / first offsets per source.
The report is the honest basis for the per-zone verdict
{decompressed-from-flash | ROM-copy-candidate | unique-runtime}:
"no match" is recorded as no_flash_match (не найдено ≠ опровергнуто).

Form helpers:
  dword_swap(data)          - the MFBA LE dword render (phase-1 ri vs
                              flash_data endianness fact)
  declcrc_source(raw)       - 68B clcrc line framing -> 64B payload lines
                              (mlxfwutil.clcrc_unwrap for real sections;
                              tolerant line-wise fallback for synthetic
                              sources with an odd tail)
  parse_init_records(raw)   - init-mem-dump record stream (8B BE addr +
                              4KB page) -> concatenated page data
  try_decompress(data)      - compressed-candidate probe (zlib/gzip/lzma/
                              bz2/lz4-when-available) -> {algo: bytes}

flash_sources(refs_dir) builds the full inventory for the cx5-rom cycle
refs directory: ri raw + dword-swap, flash_data raw + dword-swap, every
ITOC/DTOC section payload (+ declcrc for clcrc sections, + dword-swap, +
decompressed forms when a payload parses as a compression container), and
the phase-1 init/boot pages (raw + parsed page data).
"""

import bz2
import gzip
import lzma
import zlib
from pathlib import Path

import mlxfwutil

BLOCK = 4096
RECORD_HDR = 8
PAGE = 4096


def dword_swap(data):
    out = bytearray(data)
    for off in range(0, len(out) - 3, 4):
        out[off], out[off + 1], out[off + 2], out[off + 3] = \
            out[off + 3], out[off + 2], out[off + 1], out[off]
    return bytes(out)


def declcrc_source(raw):
    try:
        payload, _tail = mlxfwutil.clcrc_unwrap(raw)
        return payload
    except ValueError:
        pass
    out = bytearray()
    for off in range(0, len(raw) - 68 + 1, 68):
        out += raw[off:off + 64]
    return bytes(out)


def parse_init_records(raw):
    out = bytearray()
    off = 0
    while off + RECORD_HDR + PAGE <= len(raw):
        out += raw[off + RECORD_HDR:off + RECORD_HDR + PAGE]
        off += RECORD_HDR + PAGE
    return bytes(out)


def try_decompress(data):
    forms = {}
    probes = (
        ("zlib", lambda d: zlib.decompress(d)),
        ("zlib-raw", lambda d: zlib.decompressobj(-15).decompress(d)),
        ("gzip", lambda d: gzip.decompress(d)),
        ("lzma", lambda d: lzma.decompress(d)),
        ("bz2", lambda d: bz2.decompress(d)),
    )
    for name, fn in probes:
        try:
            out = fn(data)
        except Exception:
            continue
        if out:
            forms[name] = out
    return forms


def _iter_windows(zone_bytes, block):
    for off in range(0, len(zone_bytes), block):
        yield off, zone_bytes[off:off + block]


def match_forms(zone_bytes, sources, block=BLOCK):
    windows = list(_iter_windows(zone_bytes, block))
    degenerate = [
        off for off, win in windows
        if not win.strip(b"\x00") or not win.strip(b"\xff")
    ]
    deg = set(degenerate)
    forms = {}
    for name, src in sources.items():
        matched = 0
        first_zone_off = None
        first_src_off = None
        for zoff, win in windows:
            if zoff in deg:
                continue
            pos = src.find(win)
            if pos >= 0:
                matched += 1
                if first_zone_off is None:
                    first_zone_off = zoff
                    first_src_off = pos
        forms[name] = {
            "matched_windows": matched,
            "total_windows": len(windows),
            "found": matched > 0,
            "first_zone_off": first_zone_off,
            "first_src_off": first_src_off,
        }
    return {"block": block, "windows": len(windows),
            "degenerate_windows": sorted(degenerate), "forms": forms}


def classify(report):
    hits = [name for name, f in sorted(report["forms"].items()) if f["found"]]
    return hits[0] if hits else "no_flash_match"


def _section_sources(img, toc):
    out = {}
    for e in img.entries(toc):
        key = "%s_%02x" % (toc.lower(), e.type)
        try:
            payload = img.section_data(e)
        except ValueError:
            continue
        out[key + "_payload"] = payload
        out[key + "_dswap"] = dword_swap(payload)
        if e.clcrc:
            out[key + "_declcrc"] = declcrc_source(payload)
            out[key + "_declcrc_dswap"] = dword_swap(out[key + "_declcrc"])
        for algo, data in try_decompress(payload).items():
            if len(data) < 256:
                continue
            out["%s_decomp_%s" % (key, algo)] = data
    return out


def flash_sources(refs_dir):
    refs_dir = Path(refs_dir)
    inv = {}
    ri = (refs_dir / "ri_stock.bin").read_bytes()
    inv["ri_raw"] = ri
    inv["ri_dswap"] = dword_swap(ri)
    fd_path = refs_dir / "flash_data"
    if fd_path.exists():
        fd = fd_path.read_bytes()
        inv["flash_data_raw"] = fd
        inv["flash_data_dswap"] = dword_swap(fd)
    img = mlxfwutil.Image(ri, "ri")
    for toc in ("ITOC", "DTOC"):
        try:
            inv.update(_section_sources(img, toc))
        except KeyError:
            continue
    for name, fn in (("init_pages", "init_pages.bin"),
                     ("boot_pages", "boot_pages.bin")):
        p = refs_dir / fn
        if not p.exists():
            continue
        raw = p.read_bytes()
        inv[name + "_raw"] = raw
        inv[name + "_data"] = parse_init_records(raw)
    return inv


def zone_report(zone_bytes, refs_dir, block=BLOCK):
    inv = flash_sources(refs_dir)
    return match_forms(zone_bytes, inv, block=block)
