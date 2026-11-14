#!/usr/bin/env python3
# Разбор boot_record пары CX-7 28.33.0751/0800 + кросс-ген сравнение с
# CX-5/6 (securefw-arc-a task-05). Метод — sparse BE-DW init-таблицы
# журнала 2026-09-20-fw-iron-boot-chain.md: регион [0x100,0x500)
# (граница = HW-ptr tools=0x500), ненулевые/не-стёртые BE-DW слова,
# паттерн-извлечение CR-init записей (addr, value, count), серии
# ненулевых слов (конфиг-блоки), повторённые 16B-блобы, трейлер-слово
# (последнее ненулевое; extent = trailer_off+4 — у пары ровно 0x3f4 =
# getBootRecordSize(CX7) mstflint fs4_ops.cpp:4411). Пословный дифф пары
# с классификацией сайтов (cr_entry[k] | trailer | standalone).
# usage: bootrec_parse.py <a.bin> <b.bin> [--ref r.bin ...] [--json out]
import argparse
import json
import struct
import sys
from pathlib import Path

REC_OFF = 0x100
TOOLS_OFF = 0x500
REGION_LEN = TOOLS_OFF - REC_OFF
CX7_BOOTREC_SIZE = 0x3F4  # mstflint getBootRecordSize(CT_CONNECTX7)
ERASED = 0xFFFFFFFF
ADDR_CLASSES = (0x1868, 0x30D0)  # CR-addr верхние 16 бит (CX-6 / CX-6Dx+CX-7)
COUNT_MAX = 0x3F


def _words(region):
    n = len(region) // 4
    return struct.unpack(">%dI" % n, region[:n * 4])


def sparse_words(region):
    """Non-erased (≠ 0xFF..FF) BE-DWs: [(off, value)] (2026-09-20 method)."""
    return [(4 * i, w) for i, w in enumerate(_words(region))
            if w != ERASED]


def nonzero_words(region):
    return [(off, w) for off, w in sparse_words(region) if w != 0]


def cr_init_entries(region):
    """(addr, value, count) init records: addr word whose top-16 is a known
    CR-address class, followed by a value word and a small count word.
    Pattern-based (no fixed stride): matches stride-3 (CX-5/6 style) and
    stride-4 (CX-7 pair style) layouts."""
    ws = _words(region)
    out = []
    for i in range(len(ws) - 2):
        addr_class = ws[i] >> 16
        if addr_class not in ADDR_CLASSES:
            continue
        value, count = ws[i + 1], ws[i + 2]
        if value == ERASED or not (1 <= count <= COUNT_MAX):
            continue
        out.append({"off": 4 * i, "addr": ws[i], "value": value,
                    "count": count, "addr_class": addr_class})
    return out


def nonzero_runs(region, min_words=4):
    """Runs of consecutive nonzero (and non-erased) words; the dense
    config blocks. On the CX-7 pair the whole 0x3f4 extent is written
    (zero padding), so runs are counted over nonzero words, not
    non-erased."""
    ws = _words(region)
    runs = []
    i = 0
    while i < len(ws):
        if ws[i] != 0 and ws[i] != ERASED:
            j = i
            while j < len(ws) and ws[j] != 0 and ws[j] != ERASED:
                j += 1
            if j - i >= min_words:
                runs.append({"start": 4 * i, "end": 4 * j,
                             "nwords": j - i})
            i = j
        else:
            i += 1
    return runs


def repeated_blobs(region, size=16, min_count=2):
    """Repeating non-uniform blobs (16B default) at 4B alignment."""
    seen = {}
    for off in range(0, len(region) - size + 1, 4):
        chunk = region[off:off + size]
        if len(set(chunk)) == 1:
            continue
        seen.setdefault(chunk, []).append(off)
    return [{"offs": offs, "hex": chunk.hex()}
            for chunk, offs in sorted(seen.items(), key=lambda kv: kv[1][0])
            if len(offs) >= min_count]


def parse_bootrec(region):
    ws = _words(region)
    sparse = sum(1 for w in ws if w != ERASED)
    nz = [(4 * i, w) for i, w in enumerate(ws) if w not in (0, ERASED)]
    runs = nonzero_runs(region)
    config_block = max(runs, key=lambda r: r["nwords"]) if runs else None
    trailer_off, trailer_val = nz[-1] if nz else (None, None)
    return {
        "region_len": len(region),
        "word0": ws[0] if ws else None,
        "sparse": sparse,
        "nonzero": len(nz),
        "cr_entries": cr_init_entries(region),
        "runs": runs,
        "config_block": config_block,
        "repeated_blobs": repeated_blobs(region),
        "trailer": {
            "off": trailer_off,
            "value": trailer_val,
            "tag16_class": trailer_val is not None and trailer_val <= 0xFFFF,
        },
        "extent": None if trailer_off is None else trailer_off + 4,
    }


def _site(off, parsed):
    # Entry window is [off, off+8] (addr/value/count); the stride-4 pad
    # word at off+12 is deliberately NOT included — a pad-word diff would
    # classify as "standalone" (pads are identical in the current pair,
    # so this choice has no effect on observed data).
    for k, e in enumerate(parsed["cr_entries"]):
        if e["off"] <= off <= e["off"] + 8:
            return "cr_entry[%d]" % k
    tr = parsed["trailer"]
    if tr["off"] is not None and off == tr["off"]:
        return "trailer"
    return "standalone"


def diff_pair(ra, rb):
    pa = parse_bootrec(ra)
    n = min(len(ra), len(rb)) // 4
    wa = struct.unpack(">%dI" % n, ra[:n * 4])
    wb = struct.unpack(">%dI" % n, rb[:n * 4])
    rows = []
    bytes_delta = 0
    for i in range(n):
        if wa[i] == wb[i]:
            continue
        rows.append({"off": 4 * i, "a": "0x%08x" % wa[i],
                     "b": "0x%08x" % wb[i], "site": _site(4 * i, pa)})
        bytes_delta += sum(1 for x, y in zip(ra[4 * i:4 * i + 4],
                                             rb[4 * i:4 * i + 4]) if x != y)
    return {"bytes_delta": bytes_delta, "words_delta": len(rows),
            "rows": rows}


def fingerprint(region):
    p = parse_bootrec(region)
    return {
        "word0": p["word0"],
        "sparse": p["sparse"],
        "nonzero": p["nonzero"],
        "cr_entries": len(p["cr_entries"]),
        "addr_classes": sorted({e["addr_class"] for e in p["cr_entries"]}),
        "value_classes": sorted({e["value"] >> 16 for e in p["cr_entries"]}),
        "runs": len(p["runs"]),
        "config_block": ({"start": "0x%x" % p["config_block"]["start"],
                          "nwords": p["config_block"]["nwords"]}
                         if p["config_block"] else None),
        "trailer": {"off": p["trailer"]["off"],
                    "value": ("0x%08x" % p["trailer"]["value"]
                              if p["trailer"]["value"] is not None else None),
                    "tag16_class": p["trailer"]["tag16_class"]},
        "extent": p["extent"],
        "tag16": p["trailer"]["tag16_class"],
    }


def longest_common_run(a, b):
    """(size, off_a, off_b) of the longest common byte run."""
    best = (0, 0, 0)
    for i in range(len(a)):
        for j in range(len(b)):
            k = 0
            while (i + k < len(a) and j + k < len(b)
                   and a[i + k] == b[j + k]):
                k += 1
            if k > best[0]:
                best = (k, i, j)
    return best


def build_report(a_path, b_path, ref_paths):
    buf_a = Path(a_path).read_bytes()
    buf_b = Path(b_path).read_bytes()
    ra, rb = buf_a[REC_OFF:TOOLS_OFF], buf_b[REC_OFF:TOOLS_OFF]
    pair = diff_pair(ra, rb)
    pa, pb = parse_bootrec(ra), parse_bootrec(rb)
    refs = []
    for rp in ref_paths:
        reg = Path(rp).read_bytes()[REC_OFF:TOOLS_OFF]
        refs.append({"path": Path(rp).name, "fingerprint": fingerprint(reg)})
    lcr = None
    if pa["config_block"] and refs:
        cb_a = ra[pa["config_block"]["start"]:pa["config_block"]["end"]]
        ref_regs = [Path(rp).read_bytes()[REC_OFF:TOOLS_OFF]
                    for rp in ref_paths]
        lcr = []
        for rp, reg in zip(ref_paths, ref_regs):
            rp_parsed = parse_bootrec(reg)
            cb = (reg[rp_parsed["config_block"]["start"]:
                      rp_parsed["config_block"]["end"]]
                  if rp_parsed["config_block"] else b"")
            size, ia, ib = longest_common_run(cb_a, cb) if cb else (0, 0, 0)
            lcr.append({"ref": Path(rp).name, "run": size})
    return {
        "meta": {
            "rec_off": REC_OFF, "region_len": REGION_LEN,
            "cx7_bootrec_size_mstflint": CX7_BOOTREC_SIZE,
            "a": {"path": Path(a_path).name, "parse": pa},
            "b": {"path": Path(b_path).name, "parse": pb},
        },
        "pair": pair,
        "refs": refs,
        "config_common_runs": lcr,
    }


def _fmt_parse(p):
    tr = p["trailer"]
    return ("word0=0x%08x sparse=%d nonzero=%d cr=%d runs=%d "
            "trailer@+0x%x=0x%08x tag16=%s extent=0x%x") % (
        p["word0"], p["sparse"], p["nonzero"], len(p["cr_entries"]),
        len(p["runs"]), tr["off"] or 0, tr["value"] or 0,
        tr["tag16_class"], p["extent"] or 0)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="boot_record pair parse/diff + cross-gen fingerprints")
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--ref", action="append", default=[],
                    help="reference image (CX-5/6) for cross-gen compare")
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args(argv)

    rep = build_report(args.a, args.b, args.ref)
    print("== boot_record [%#x,%#x) ==" % (REC_OFF, TOOLS_OFF))
    print("A:", _fmt_parse(rep["meta"]["a"]["parse"]))
    print("B:", _fmt_parse(rep["meta"]["b"]["parse"]))
    print("-- CR-init entries --")
    for side in ("a", "b"):
        for k, e in enumerate(rep["meta"][side]["parse"]["cr_entries"]):
            print("  %s [%d] +0x%02x addr=0x%08x value=0x%08x count=%d" % (
                side.upper(), k, e["off"], e["addr"], e["value"], e["count"]))
    print("-- pair diff: %d words / %d bytes --" % (
        rep["pair"]["words_delta"], rep["pair"]["bytes_delta"]))
    for row in rep["pair"]["rows"]:
        print("  +0x%03x %s -> %s  (%s)" % (
            row["off"], row["a"], row["b"], row["site"]))
    for r in rep["refs"]:
        fp = r["fingerprint"]
        print("-- ref %s: word0=0x%08x cr=%d addr=%s extent=%s tag16=%s" % (
            r["path"], fp["word0"], fp["cr_entries"],
            [hex(c) for c in fp["addr_classes"]],
            hex(fp["extent"]) if fp["extent"] else None, fp["tag16"]))
    if rep["config_common_runs"]:
        print("-- config-block common byte runs vs refs --")
        for c in rep["config_common_runs"]:
            print("  %s: %d B" % (c["ref"], c["run"]))
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(rep, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
