#!/usr/bin/env python3
# Дизасм-пайплайн бут-регионов securefw-arc-b (task-02): boot2 (Carmel-
# контейнер, parse_boot2 арки A) и ITOC-секций BOOT3 0x0f / IRON_PREP 0x05
# (mlxfwutil.Image; бут-секции без clcrc, MAIN-класс — через
# clcrc_unwrap). Листинг формата корпуса (`scripts/corpus/disasm_build.py`)
# + аннотация профиля (`scripts/irisc/profiles.py`); unknown-строки
# декодера (`op0x../alu.0x..`) сохраняются как есть (правило арки).
# Адресация: boot2 — base=0 (body-relative word-off, пространство sidecar
# Task 3); секции — base=ITOC param0 (rt-пространство: entry=param1,
# вызовы ниже load-базы = H-W8-сигнал).
# call_targets — прямые переходы op 0x25 (call/jump) для call-graph;
# xref_constants — 32-битные константы трёх идиом (addi lo + addi.hi hi
# (k≤3, RS==RD) — прецедент rt_calib.py/cert_consumers.py; set2 rd,rs,hi +
# set3 rX,rd,lo (k≤4) — прецедент cert_consumers.set23_pairs (CX-6);
# set3 rd,zero,lo + set2 rd,rd,hi (k≤4) — CX-7 boot2-идиома: set3-очистка
# младших, set2-вставка старших (ISA 010: set2=биты 31..16, set3=15..0)),
# классифицированные по ADDR_CLASSES (load-базы 0x20xxxxxx, CR 0x30d0xxxx/
# 0x1868xxxx, value-класс 0x0c1xxxxx, RAM 0x0008_0000+).
# usage: boot_disasm.py --image IMG --region {boot2,section}
#        [--section 0xNN] --out OUT [--calls-out F]
#        [--boot2-off 0x1000] [--profile cx7|cx6dx|none]
import argparse
import importlib.util
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import mlxfwutil  # noqa: E402
from scripts.irisc import disasm  # noqa: E402
from scripts.irisc.irisc_dis import s16  # noqa: E402
from scripts.irisc.profiles import annotate, load_profile  # noqa: E402

BOOT2_OFF = 0x1000

ADDR_CLASSES = (
    ("load_base", 0x20000000, 0x21FFFFFF),
    ("cr_30d0", 0x30D00000, 0x30D0FFFF),
    ("cr_1868", 0x18680000, 0x1868FFFF),
    ("cr_val_0c1", 0x0C100000, 0x0C1FFFFF),
    ("ram_low", 0x00080000, 0x001FFFFF),
)

_boot2_probe = None


def _probe():
    global _boot2_probe
    if _boot2_probe is None:
        path = (REPO / "scripts" / "probes" / "securefw-arc-a"
                / "boot2_probe.py")
        spec = importlib.util.spec_from_file_location("boot2_probe", path)
        _boot2_probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_boot2_probe)
    return _boot2_probe


def words_of(data):
    return struct.unpack_from(">%dI" % (len(data) // 4), data, 0)


def disasm_region(words, base, profile=None, header=None):
    lines = list(header or [])
    for i, w in enumerate(words):
        addr = (base + 4 * i) & 0xFFFFFFFF
        lines.append("%08x  %08x  %s" % (addr, w, disasm(w, addr)))
    text = "\n".join(lines)
    if profile is None:
        return text
    if isinstance(profile, str):
        profile = load_profile(profile)
    return annotate(text, profile)


def call_targets(words, base):
    out = []
    for i, w in enumerate(words):
        if (w >> 26) != 0x25:
            continue
        off = (base + 4 * i) & 0xFFFFFFFF
        text = disasm(w, off)
        out.append({"off": off, "word": w, "kind": text.split()[0],
                    "target": int(text.rsplit("0x", 1)[1], 16)})
    return out


def _pairs_addi_hi(words):
    out = []
    n = len(words)
    for i, w in enumerate(words):
        if (w >> 26) not in (0x00, 0x01):
            continue
        rd = (w >> 16) & 0x1F
        lo = w & 0xFFFF
        for k in range(1, 4):
            j = i + k
            if j >= n:
                break
            wp = words[j]
            if (wp >> 26) not in (0x02, 0x03):
                continue
            if ((wp >> 21) & 0x1F) != rd:
                continue
            val = (((wp & 0xFFFF) << 16) + s16(lo)) & 0xFFFFFFFF
            out.append((i, val, "addi/addi.hi"))
            break
    return out


def _pairs_set23(words):
    out = []
    n = len(words)
    for i, w in enumerate(words):
        if (w >> 26) != 0x09:
            continue
        rd = (w >> 16) & 0x1F
        hi = w & 0xFFFF
        for k in range(1, 5):
            j = i + k
            if j >= n:
                break
            wp = words[j]
            if (wp >> 26) != 0x08:
                continue
            if ((wp >> 21) & 0x1F) != rd:
                continue
            out.append((i, ((hi << 16) | (wp & 0xFFFF)) & 0xFFFFFFFF,
                        "set2/set3"))
            break
    return out


def _pairs_set32(words):
    out = []
    n = len(words)
    for i, w in enumerate(words):
        if (w >> 26) != 0x08:
            continue
        if ((w >> 21) & 0x1F) != 0:
            continue
        rd = (w >> 16) & 0x1F
        lo = w & 0xFFFF
        for k in range(1, 5):
            j = i + k
            if j >= n:
                break
            wp = words[j]
            if (wp >> 26) != 0x09:
                continue
            if (wp >> 16) & 0x1F != rd or (wp >> 21) & 0x1F != rd:
                continue
            out.append((i, (((wp & 0xFFFF) << 16) | lo) & 0xFFFFFFFF,
                        "set3/set2"))
            break
    return out


def xref_constants(words, base):
    out = {}
    pairs = (_pairs_addi_hi(words) + _pairs_set23(words)
             + _pairs_set32(words))
    for i, val, idiom in pairs:
        for name, lo, hi in ADDR_CLASSES:
            if lo <= val <= hi:
                out.setdefault(name, []).append(
                    {"off": (base + 4 * i) & 0xFFFFFFFF, "value": val,
                     "idiom": idiom})
                break
    return out


def is_unknown(w):
    r = disasm(w, 0)
    return r.startswith("op0x") or r.startswith("alu.0x")


def open_image(buf, name="<mem>"):
    return mlxfwutil.Image(buf, name)


def load_region(buf, region="boot2", boot2_off=BOOT2_OFF):
    if region != "boot2":
        raise ValueError("region %r: use load_section() for ITOC sections"
                         % region)
    p = _probe().parse_boot2(buf, boot2_off)
    words = words_of(p["body"]) if p["status"] == "ok" else ()
    return {"status": p["status"], "words": words, "base": 0,
            "meta": {k: v for k, v in p.items() if k != "body"}}


def load_section(img, section):
    e = img.find_entry("ITOC", section)
    meta = {"type": e.type, "size": e.size, "addr": e.addr,
            "load": e.param0, "entry": e.param1, "clcrc": bool(e.clcrc)}
    if e.zipped:
        return {"status": "SKIPPED-zipped", "words": (), "base": 0,
                "meta": meta}
    data = img.section_data(e)
    if e.clcrc:
        data, _tail = mlxfwutil.clcrc_unwrap(data)
    return {"status": "ok", "words": words_of(data), "base": e.param0,
            "meta": meta}


def region_counters(words, base):
    calls = call_targets(words, base)
    xref = xref_constants(words, base)
    unknown = sum(1 for w in words if is_unknown(w))
    return {
        "words": len(words),
        "unknown": unknown,
        "unknown_frac": round(unknown / len(words), 4) if words else 0.0,
        "call_sites": len(calls),
        "call_targets": len({c["target"] for c in calls}),
        "xref": {k: len(v) for k, v in xref.items()},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="boot2/BOOT3/IRON_PREP disasm pipeline (securefw-arc-b)")
    ap.add_argument("--image", required=True)
    ap.add_argument("--region", choices=("boot2", "section"), required=True)
    ap.add_argument("--section", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--calls-out", default=None)
    ap.add_argument("--boot2-off", type=lambda s: int(s, 0),
                    default=BOOT2_OFF)
    ap.add_argument("--profile", default="cx7",
                    help="profile name or 'none'")
    args = ap.parse_args(argv)

    buf = Path(args.image).read_bytes()
    if args.region == "boot2":
        reg = load_region(buf, "boot2", boot2_off=args.boot2_off)
        label = "boot2 @%#x" % args.boot2_off
        m = reg["meta"]
        header = [
            "# image: %s" % args.image,
            "# region: %s dw0=%08x dw1=%x size=%#x crc_ok=%s"
            % (label, m["dw0"] or 0, m["dw1"] or 0, m["size"] or 0,
               m["crc_ok"]),
            "# base: %#x (body-relative)" % reg["base"],
            "# profile: %s" % args.profile,
        ]
    else:
        if args.section is None:
            ap.error("--section is required for --region section")
        reg = load_section(open_image(buf, args.image), args.section)
        label = "section 0x%02x" % args.section
        m = reg["meta"]
        header = [
            "# image: %s" % args.image,
            "# region: %s size=%#x addr=%#x clcrc=%d"
            % (label, m["size"], m["addr"], m["clcrc"]),
            "# base: %#x (param0/load) entry: %#x" % (m["load"], m["entry"]),
            "# profile: %s" % args.profile,
        ]
    if reg["status"] != "ok":
        print("%s: status=%s" % (args.image, reg["status"]),
              file=sys.stderr)
        return 1

    profile = None if args.profile == "none" else args.profile
    text = disasm_region(reg["words"], reg["base"], profile, header=header)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text + "\n")

    calls = call_targets(reg["words"], reg["base"])
    xref = xref_constants(reg["words"], reg["base"])
    c = region_counters(reg["words"], reg["base"])
    print("%s %s: words=%d unknown=%d (%.2f%%) call_sites=%d "
          "call_targets_distinct=%d" % (args.image, label, c["words"],
                                        c["unknown"],
                                        100 * c["unknown_frac"],
                                        c["call_sites"], c["call_targets"]))
    print("xref: %s" % (", ".join("%s=%d" % kv for kv in
                                  sorted(c["xref"].items())) or "none"))
    print("listing -> %s" % out)
    if args.calls_out:
        calls_out = Path(args.calls_out)
        calls_out.parent.mkdir(parents=True, exist_ok=True)
        calls_out.write_text(json.dumps(
            {"image": args.image, "region": label, "base": reg["base"],
             "words": len(reg["words"]), "calls": calls, "xref": xref},
            indent=1) + "\n")
        print("calls -> %s" % calls_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
