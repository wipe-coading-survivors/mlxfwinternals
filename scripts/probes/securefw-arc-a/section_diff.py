#!/usr/bin/env python3
# Посекционный дифф пары образов Mellanox (FS3/FS4) + boot-окон
# (securefw-arc-a task-02): ITOC byte-diff -> таблица per-section
# {identical|different|absent, md5, B-delta, word-delta, % секции};
# cl=1-секции сравниваются после de-clcrc (payload, без 68B-фрейминга);
# zipped-секции сравниваются как raw (флаг в строке). Дополнительно строки
# boot_record ([0x100,0x1000) + плотный экстент) и boot2 (@0x1000, размер
# из DW1: (4+DW1)*4). Для different iRISC-секций (домены корпуса,
# DOMAIN_PRIOR) — счётчики дизасм-диффа: changed_words/tail_words
# (1 слово = 1 строка дизасма) и функции по boundaries.find_functions
# (идентификатор — entry_dc): funcs_changed/funcs_only_a/b + drift-сводка
# профиля. Позиционный дифф (не SequenceMatcher: 1.28M слов непрактично).
# usage: section_diff.py <a.bin> <b.bin> [--json out.json] [--profile cx7]
#       [--no-boot]
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import mlxfwutil as U
from scripts.corpus.boundaries import find_functions
from scripts.corpus.disasm_build import disasm_section, recount_delta
from scripts.corpus.extract import DOMAIN_PRIOR
from scripts.irisc.profiles import ProfileError, load_profile
from scripts.probes.toc_probe import SECT_NAMES

BOOT_REC_OFF = 0x100
BOOT2_OFF = 0x1000


def md5(data):
    return hashlib.md5(data).hexdigest() if data is not None else None


def payload_of(img, e):
    raw = img.section_data(e)
    if e.zipped:
        return raw, "zipped-raw"
    if e.clcrc:
        payload, _tail = U.clcrc_unwrap(raw)
        return payload, "clcrc"
    return raw, "raw"


def byte_delta(pa, pb):
    min_len = min(len(pa), len(pb))
    if min_len:
        xor = (int.from_bytes(pa[:min_len], "big")
               ^ int.from_bytes(pb[:min_len], "big"))
        bytes_delta = min_len - xor.to_bytes(min_len, "big").count(0)
    else:
        bytes_delta = 0
    words_common = min_len // 4
    words_delta = 0
    if words_common:
        wa = struct.unpack_from(">%dI" % words_common, pa, 0)
        wb = struct.unpack_from(">%dI" % words_common, pb, 0)
        words_delta = sum(1 for x, y in zip(wa, wb) if x != y)
    return {
        "min_len": min_len,
        "bytes_delta": bytes_delta,
        "words_common": words_common,
        "words_delta": words_delta,
        "tail_bytes": abs(len(pa) - len(pb)),
        "pct": round(100.0 * bytes_delta / min_len, 4) if min_len else 0.0,
    }


def section_rows(img_a, img_b):
    ents_a = {e.type: e for e in img_a.entries("ITOC") if e.type != 0xFF}
    ents_b = {e.type: e for e in img_b.entries("ITOC") if e.type != 0xFF}
    rows = []
    for typ in sorted(set(ents_a) | set(ents_b)):
        row = {
            "section": "%02X" % typ,
            "type": typ,
            "name": SECT_NAMES.get(typ, "?"),
            "domain": DOMAIN_PRIOR.get(typ, "data"),
            "status": None,
            "only_in": None,
            "cl": None,
            "zipped": None,
            "md5_a": None, "md5_b": None,
            "size_a": None, "size_b": None,
            "raw_size_a": None, "raw_size_b": None,
            "delta": None,
            "status_reason": "",
        }
        ea, eb = ents_a.get(typ), ents_b.get(typ)
        if ea is None or eb is None:
            row["status"] = "absent"
            side = "a" if eb is None else "b"
            row["only_in"] = side
            img = img_a if side == "a" else img_b
            e = ea if side == "a" else eb
            row["raw_size_%s" % side] = e.size
            try:
                p, _basis = payload_of(img, e)
            except ValueError as exc:
                row["status_reason"] = str(exc)
            else:
                row["md5_%s" % side] = md5(p)
                row["size_%s" % side] = len(p)
                row["cl"] = bool(e.clcrc)
                row["zipped"] = bool(e.zipped)
            rows.append(row)
            continue
        row["cl"] = bool(ea.clcrc or eb.clcrc)
        row["zipped"] = bool(ea.zipped or eb.zipped)
        row["raw_size_a"], row["raw_size_b"] = ea.size, eb.size
        try:
            pa, _ = payload_of(img_a, ea)
            pb, _ = payload_of(img_b, eb)
        except ValueError as exc:
            row["status"] = "error"
            row["status_reason"] = str(exc)
            rows.append(row)
            continue
        row["md5_a"], row["md5_b"] = md5(pa), md5(pb)
        row["size_a"], row["size_b"] = len(pa), len(pb)
        row["delta"] = byte_delta(pa, pb)
        row["status"] = "identical" if pa == pb else "different"
        rows.append(row)
    return rows


def _dense_extent(region):
    last = -1
    for i in range(len(region) - 1, -1, -1):
        if region[i] != 0xFF:
            last = i
            break
    return last + 1


def _boot2_region(buf, off):
    if off + 8 > len(buf):
        return None, None, None, "no header window"
    dw0, dw1 = struct.unpack_from(">II", buf, off)
    if dw0 == 0xFFFFFFFF and dw1 == 0xFFFFFFFF:
        return None, dw0, dw1, "erased"
    size = (4 + dw1) * 4
    if off + size > len(buf):
        return None, dw0, dw1, "truncated (size %#x overruns buffer)" % size
    return buf[off:off + size], dw0, dw1, ""


def _boot_row(section, name, pa, pb, extra=None):
    row = {
        "section": section,
        "name": name,
        "domain": "boot",
        "status": None,
        "only_in": None,
        "md5_a": md5(pa),
        "md5_b": md5(pb),
        "size_a": None if pa is None else len(pa),
        "size_b": None if pb is None else len(pb),
        "delta": None,
        "status_reason": "",
    }
    row.update(extra or {})
    if pa is None or pb is None:
        row["status"] = "absent"
        row["only_in"] = "a" if pb is None else "b"
        return row
    row["delta"] = byte_delta(pa, pb)
    row["status"] = "identical" if pa == pb else "different"
    return row


def boot_rows(buf_a, buf_b, rec_off=BOOT_REC_OFF, boot2_off=BOOT2_OFF):
    rows = []
    rec_a = buf_a[rec_off:boot2_off] if len(buf_a) >= boot2_off else None
    rec_b = buf_b[rec_off:boot2_off] if len(buf_b) >= boot2_off else None
    rows.append(_boot_row("BOOT_RECORD", "BOOT_RECORD", rec_a, rec_b, {
        "dense_extent_a": _dense_extent(rec_a) if rec_a else None,
        "dense_extent_b": _dense_extent(rec_b) if rec_b else None,
    }))
    reg_a, dw0a, dw1a, err_a = _boot2_region(buf_a, boot2_off)
    reg_b, dw0b, dw1b, err_b = _boot2_region(buf_b, boot2_off)
    row = _boot_row("BOOT2", "BOOT2", reg_a, reg_b, {
        "dw0": "0x%08x" % dw0a if dw0a is not None else
               ("0x%08x" % dw0b if dw0b is not None else None),
        "dw1_a": dw1a, "dw1_b": dw1b,
    })
    if err_a or err_b:
        row["status_reason"] = "; ".join(x for x in (err_a, err_b) if x)
    rows.append(row)
    return rows


def _func_spans(funcs, base):
    spans = {}
    for f in funcs.funcs:
        spans[f.entry_dc] = ((f.entry_dc - base) // 4,
                             (f.end_dc - base) // 4)
    return spans


def disasm_delta(pa, pb, base_a, base_b, param1_a, param1_b, profile):
    lines_a = disasm_section(pa, base_a)
    lines_b = disasm_section(pb, base_b)
    funcs_a = find_functions(lines_a, [param1_a] if param1_a else [])
    funcs_b = find_functions(lines_b, [param1_b] if param1_b else [])
    words_common = min(len(pa), len(pb)) // 4
    wa = struct.unpack_from(">%dI" % words_common, pa, 0)
    wb = struct.unpack_from(">%dI" % words_common, pb, 0)
    changed_set = {i for i in range(words_common) if wa[i] != wb[i]}
    spans_a = _func_spans(funcs_a, base_a)
    spans_b = _func_spans(funcs_b, base_b)
    common = set(spans_a) & set(spans_b)
    changed_common = 0
    for entry in common:
        hit = False
        for s, e in (spans_a[entry], spans_b[entry]):
            if s >= words_common or e >= words_common:
                hit = True
                break
            if any(i in changed_set for i in range(s, e + 1)):
                hit = True
                break
        if hit:
            changed_common += 1
    only_a = len(set(spans_a) - set(spans_b))
    only_b = len(set(spans_b) - set(spans_a))
    out = {
        "profile": getattr(profile, "name", None),
        "base_a": base_a, "base_b": base_b,
        "words_a": len(pa) // 4, "words_b": len(pb) // 4,
        "changed_words": len(changed_set),
        "tail_words": abs(len(pa) - len(pb)) // 4,
        "funcs_a": len(spans_a), "funcs_b": len(spans_b),
        "funcs_common": len(common),
        "funcs_changed_common": changed_common,
        "funcs_only_a": only_a, "funcs_only_b": only_b,
        "funcs_changed": changed_common + only_a + only_b,
    }
    if profile is not None and hasattr(profile, "census"):
        drift = {}
        for side, dc, lines in (("a", pa, lines_a), ("b", pb, lines_b)):
            d = recount_delta(dc, profile, lines=lines)
            drift[side] = {
                "flag": d["flag"],
                "new_ops": d["new_ops"],
                "unknown_words": sum(d["counts"].values()),
            }
        out["drift"] = drift
    else:
        out["drift"] = None
    return out


def _try_profile(name):
    if not name:
        return None
    try:
        return load_profile(name)
    except ProfileError:
        return None


def _attach_disasm(img_a, img_b, rows, profile):
    for row in rows:
        if row["domain"] != "iRISC" or row["status"] != "different":
            continue
        ea = img_a.find_entry("ITOC", row["type"])
        eb = img_b.find_entry("ITOC", row["type"])
        try:
            pa, _ = payload_of(img_a, ea)
            pb, _ = payload_of(img_b, eb)
        except ValueError:
            continue
        if not pa or not pb:
            continue
        row["disasm"] = disasm_delta(pa, pb, ea.param0, eb.param0,
                                     ea.param1, eb.param1, profile)


def build_report_bytes(buf_a, buf_b, profile_name="cx7", boot=True):
    img_a, img_b = U.Image(buf_a), U.Image(buf_b)
    rows = section_rows(img_a, img_b)
    profile = _try_profile(profile_name)
    _attach_disasm(img_a, img_b, rows, profile)
    return {
        "a": {"path": "<mem>", "md5": md5(buf_a), "size": len(buf_a)},
        "b": {"path": "<mem>", "md5": md5(buf_b), "size": len(buf_b)},
        "fmt": img_a.fmt,
        "profile": profile_name,
        "sections": rows,
        "boot": boot_rows(buf_a, buf_b) if boot else None,
    }


def build_report(path_a, path_b, profile_name="cx7", boot=True):
    buf_a = Path(path_a).read_bytes()
    buf_b = Path(path_b).read_bytes()
    rep = build_report_bytes(buf_a, buf_b, profile_name=profile_name,
                             boot=boot)
    rep["a"]["path"] = str(path_a)
    rep["b"]["path"] = str(path_b)
    return rep


def print_table(rep):
    print("a: %s md5=%s size=%d" % (rep["a"]["path"], rep["a"]["md5"],
                                    rep["a"]["size"]))
    print("b: %s md5=%s size=%d" % (rep["b"]["path"], rep["b"]["md5"],
                                    rep["b"]["size"]))
    hdr = ("sec  name                status     size_a    size_b    "
           "Bdelta    wdelta   tail    wcommon      %")
    print("\n== sections")
    print(hdr)
    for r in rep["sections"]:
        d = r["delta"]
        ds = ("%-9d %-8d %-9d %-6d %6.2f" % (
            d["bytes_delta"], d["words_delta"], d["tail_bytes"],
            d["words_common"], d["pct"])) if d else "-"
        flags = ("cl " if r["cl"] else "   ") + ("zip" if r["zipped"] else "")
        print("%-4s %-19s %-10s %-9d %-9d %s %s" % (
            r["section"], r["name"], r["status"],
            r["size_a"] if r["size_a"] is not None else -1,
            r["size_b"] if r["size_b"] is not None else -1, ds, flags))
        if r.get("disasm"):
            dis = r["disasm"]
            print("     disasm: words %d/%d changed=%d tail=%d | funcs "
                  "%d/%d common=%d changed=%d only_a=%d only_b=%d" % (
                      dis["words_a"], dis["words_b"], dis["changed_words"],
                      dis["tail_words"], dis["funcs_a"], dis["funcs_b"],
                      dis["funcs_common"], dis["funcs_changed"],
                      dis["funcs_only_a"], dis["funcs_only_b"]))
    if rep.get("boot"):
        print("\n== boot windows")
        print(hdr)
        for r in rep["boot"]:
            d = r["delta"]
            ds = ("%-9d %-8d %-9d %-6d %6.2f" % (
                d["bytes_delta"], d["words_delta"], d["tail_bytes"],
                d["words_common"], d["pct"])) if d else "-"
            extra = ""
            if r["section"] == "BOOT2" and r.get("dw0"):
                extra = " dw0=%s dw1=%s/%s" % (
                    r["dw0"],
                    "0x%x" % r["dw1_a"] if r["dw1_a"] is not None else "-",
                    "0x%x" % r["dw1_b"] if r["dw1_b"] is not None else "-")
            if r["section"] == "BOOT_RECORD":
                extra = " dense=%s/%s" % (
                    "0x%x" % r["dense_extent_a"]
                    if r["dense_extent_a"] is not None else "-",
                    "0x%x" % r["dense_extent_b"]
                    if r["dense_extent_b"] is not None else "-")
            print("%-11s %-13s %-10s %-9d %-9d %s%s" % (
                r["section"], r["name"], r["status"],
                r["size_a"] if r["size_a"] is not None else -1,
                r["size_b"] if r["size_b"] is not None else -1, ds, extra))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="per-section diff of two firmware images + boot windows")
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--json", metavar="OUT", default=None,
                    help="write full report JSON here")
    ap.add_argument("--profile", default="cx7",
                    help="irisc profile name for disasm drift (cx7)")
    ap.add_argument("--no-boot", action="store_true")
    args = ap.parse_args(argv)
    rep = build_report(args.a, args.b, profile_name=args.profile,
                       boot=not args.no_boot)
    print_table(rep)
    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rep, indent=1) + "\n")
        print("\njson -> %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
