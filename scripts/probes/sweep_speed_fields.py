#!/usr/bin/env python3
"""Cross-image byte sweep for PRS management speed fields in CX-4/CX-4Lx
FS3 images (plan 2026-10-07-cx4lx-56-100g, task 1).

Target fields (PRS management block; mlxfwutil does not parse them, binary
offset unknown):
  management.port_info.link_speed_ena
  management.port_info.link_speed_ext_ena
  management.port_info.link_speed_ext_sup
  management.extended_port_info.link_speed_supported

Method (task-1 brief):
  * target pattern per field = values from each image's own 0x30
    (DBG_FW_INI) ini (zlib); a field absent in the ini -> expected 0x0
    (H1 hypothesis: field is 0/absent in the binary), marked with '*';
  * a byte (section, rel offset) is a raw candidate if its value matches
    the pattern for ALL images of one layout generation
    (A=12.23.1020, B=12.28.2302/4706, C=14.32.1912 + 1900 dump);
   * cross-version: a raw candidate is confirmed in another generation at
     the same rel offset, or (section 0x12 only) inside a +/-0x40 window
     around the lcl anchor (rel 0x30b; layout-shift precedent:
     12.28->14.32 -0x6c, docs/850-howto/140-fw-upgrade §8). A candidate is reported only when
     confirmed in >=2 generations, and is tiered:
       FOUND    — confirmed in all 3 generations;
       EXCLUDED — confirmed in >=2 generations but refuted ("no") by the
                  remaining one (e.g. a byte carrying the A value in 12.23
                  and 0x00 in 14.32, but not the B value in 12.28);
  * sections swept: 0x08/0x09/0x10/0x11/0x12/0x32 (config); 0x30 is
    checked as ini text (field presence), not as compressed bytes;
  * control: the same sweep on the lcl[0].eth_speeds_supported byte
    pattern must find 0x12+0x30b in all generations, otherwise the
    method is broken (exit 1).

Images: 10 vendor .bin from refs/fw/cx-4/ + slot A of the 1900 raw dump
(refs/fw/cx-4/dumps/lx_c1_final_rollback-20260919.bin; truncated dump,
slot A @0x0 verified intact, slot B erased).

Usage: python3 scripts/probes/sweep_speed_fields.py [--json OUT]
"""
import argparse
import json
import re
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from toc_probe import ITOC_HDR, find_all, bits  # noqa: E402

LCL_ANCHOR = 0x30b          # lcl[0] rel offset in 0x12 (verified, all gens)
LCL1_OFF = 0x317            # lcl[1] (2-port images only)
SHIFT_WINDOW = 0x40         # layout-shift scan window around the anchor
CONFIG_SECTS = (0x08, 0x09, 0x10, 0x11, 0x12, 0x32)
GENS = ("A", "B", "C")

IMAGES = [
    ("453A-1223", "A", "refs/fw/cx-4/fw-ConnectX4-rel-12_23_1020-MCX453A-FCA_Ax-UEFI-14.16.17-FlexBoot-3.5.504.bin"),
    ("415A-2302", "B", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_2302-MCX415A-GCA_Ax-UEFI-14.21.17-FlexBoot-3.6.102.bin"),
    ("455A-2302", "B", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-UEFI-14.21.17-FlexBoot-3.6.102.bin"),
    ("413A-4706", "B", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX413A-GCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"),
    ("416A-4706", "B", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX416A-CCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"),
    ("456E-4706", "B", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"),
    ("456F-4706", "B", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-FCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"),
    ("ACA-1912", "C", "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4121A-ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"),
    ("BCA-1912", "C", "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-BCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"),
    ("GCA-1912", "C", "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"),
    ("1900-dump", "C", "refs/fw/cx-4/dumps/lx_c1_final_rollback-20260919.bin"),
]

FIELD_RE = [
    ("ena", r"management\.port_info\.link_speed_ena\s*=\s*0x([0-9a-fA-F]+)"),
    ("ext_ena", r"management\.port_info\.link_speed_ext_ena\s*=\s*0x([0-9a-fA-F]+)"),
    ("ext_sup", r"management\.port_info\.link_speed_ext_sup\s*=\s*0x([0-9a-fA-F]+)"),
    ("sup", r"management\.extended_port_info\.link_speed_supported\s*=\s*0x([0-9a-fA-F]+)"),
]
SPEED_KEYS = ("Speed1Gb", "Speed10Gb", "Speed20Gb", "Speed25Gb",
              "Speed40Gb", "Speed50Gb", "Speed56Gb", "Speed100Gb")


def load_sections(path: str) -> dict:
    buf = open(path, "rb").read()
    itoc = find_all(buf, ITOC_HDR)[0]
    sects = {}
    i = 0
    while True:
        e = itoc + 32 + i * 32
        ent = buf[e:e + 32]
        typ = bits(ent, 0, 8)
        if typ == 0xFF:
            break
        size = bits(ent, 8, 22) * 4
        addr = bits(ent, 161, 29) * 4
        sects.setdefault(typ, buf[addr:addr + size])
        i += 1
    return sects


def prs_fields(sects: dict) -> dict:
    txt = zlib.decompress(sects[0x30]).decode("latin1")
    out = {}
    for name, rx in FIELD_RE:
        m = re.search(rx, txt)
        out[name] = (int(m.group(1), 16), True) if m else (0, False)
    lcl = {}
    for m in re.finditer(
            r"lcl\[(\d+)\]\.eth_speeds_supported\.(\w+)\s*=\s*0x([0-9a-fA-F]+)",
            txt):
        if int(m.group(3), 16):
            lcl[int(m.group(1))] = lcl.get(int(m.group(1)), 0) | (
                1 << SPEED_KEYS.index(m.group(2)))
    out["lcl"] = lcl
    return out


def gen_candidates(data, gen_imgs, pattern, sects):
    """(sect, rel) -> [images]: byte equals the pattern for every image of
    the generation that has the section."""
    out = {}
    for t in sects:
        have = [n for n in gen_imgs if t in data[n]]
        if not have:
            continue
        n = min(len(data[x][t]) for x in have)
        for off in range(n):
            if all(data[x][t][off] == pattern[x] for x in have):
                out.setdefault((t, off), []).extend(have)
    return out


def gen_match(data, gen_imgs, pattern, t, off) -> bool:
    return all(t in data[x] and off < len(data[x][t])
               and data[x][t][off] == pattern[x] for x in gen_imgs)


def window_hits(data, imgs, pattern, t, off):
    """Offsets of the +/-SHIFT_WINDOW window around the lcl anchor (0x12
    only) where the whole generation matches the pattern."""
    if t != 0x12:
        return []
    lo = max(0, LCL_ANCHOR - SHIFT_WINDOW)
    hi = min(min(len(data[x][t]) for x in imgs), LCL_ANCHOR + SHIFT_WINDOW + 1)
    return [o for o in range(lo, hi) if gen_match(data, imgs, pattern, t, o)]


def sweep_field(pattern, data, gens):
    """Returns (raw_counts, cross): per-gen raw candidate counts and the
    cross-version list (confirmed in >=2 generations; tier FOUND/EXCLUDED)."""
    raw, cands = {}, {}
    for g in GENS:
        imgs = gens[g]
        c = gen_candidates(data, imgs, pattern, CONFIG_SECTS)
        raw[g] = len(c)
        for k in c:
            cands.setdefault(k, set()).add(g)
    cross = []
    for (t, off) in sorted(cands, key=lambda k: (k[1], k[0])):
        status = {}
        for g in GENS:
            imgs = gens[g]
            if (t, off) in cands and g in cands[(t, off)]:
                status[g] = f"same@0x{off:x}"
            else:
                hits = window_hits(data, imgs, pattern, t, off)
                if len(hits) == 1:
                    status[g] = f"shifted@0x{hits[0]:x}(d={hits[0] - off:+#x})"
                elif hits:
                    status[g] = "shifted-ambig@" + "/".join(hex(h) for h in hits)
                else:
                    status[g] = "no"
        confirmed = [g for g in GENS
                     if status[g].startswith(("same@", "shifted@0x"))]
        if len(confirmed) < 2:
            continue
        refuted = [g for g in GENS if g not in confirmed]
        tier = ("FOUND" if not refuted
                else "EXCLUDED(refuted by " + ",".join(refuted) + ")")
        cross.append({"sect": t, "off": off, "tier": tier,
                      "gens": {g: status[g] for g in GENS},
                      "values": {n: (hex(data[n][t][off])
                                      if t in data[n] and off < len(data[n][t])
                                      else "-") for n, _, _ in IMAGES}})
    return raw, cross


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", metavar="OUT", help="write JSON report")
    a = ap.parse_args(argv)

    data, prs = {}, {}
    for name, gen, rel in IMAGES:
        p = ROOT / rel
        if not p.exists():
            print(f"ERROR: {p} not found", file=sys.stderr)
            return 2
        data[name] = load_sections(str(p))
        prs[name] = prs_fields(data[name])
    gens = {g: [n for n, gg, _ in IMAGES if gg == g] for g in GENS}

    print(f"== sweep_speed_fields: {len(IMAGES)} images, gens: " +
          " ".join(f"{g}={len(gens[g])}" for g in GENS))
    for g in GENS:
        print(f"  gen {g}: {' '.join(gens[g])}")
    print()

    report = {"images": {n: {"gen": g, "path": rel} for n, g, rel in IMAGES},
              "patterns": {}, "lcl_anchor": {}, "fields": {}}
    anchor_ok = 0
    print(f"lcl anchor check (0x12+0x{LCL_ANCHOR:x}, lcl[1] @0x{LCL1_OFF:x}):")
    for name, _, _ in IMAGES:
        l = prs[name]["lcl"]
        sec12 = data[name].get(0x12, b"")
        ok0 = len(sec12) > LCL_ANCHOR and sec12[LCL_ANCHOR] == l.get(0, 0)
        ok1 = None
        if 1 in l:
            ok1 = len(sec12) > LCL1_OFF and sec12[LCL1_OFF] == l[1]
        anchor_ok += ok0
        report["lcl_anchor"][name] = {
            "prs_lcl0": f"0x{l.get(0, 0):x}", "at_0x30b": ok0,
            "prs_lcl1": (f"0x{l[1]:x}" if ok1 is not None else None),
            "at_0x317": ok1}
        flag = "OK" if (ok0 and ok1 is not False) else "MISMATCH"
        l1 = f" lcl1@0x317={'OK' if ok1 else 'MISMATCH'}" if ok1 is not None else ""
        print(f"  {name:10s} lcl0=0x{l.get(0, 0):x} @0x30b: {flag}{l1}")
    print(f"  -> {anchor_ok}/{len(IMAGES)} images, 0x12+0x30b tracks PRS lcl[0]")
    print()

    print("patterns (from 0x30 ini; * = absent in ini, 0x0 assumed per H1):")
    patterns = {}
    for name, _ in FIELD_RE:
        patterns[name] = {}
    for name, _, _ in IMAGES:
        for fname, _ in FIELD_RE:
            val, present = prs[name][fname]
            patterns[fname][name] = val
            report["patterns"].setdefault(fname, {})[name] = (
                f"0x{val:x}" + ("" if present else "*"))
    for fname, _ in FIELD_RE:
        print(f"  {fname:8s}: " + " ".join(
            f"{n}=0x{patterns[fname][n]:x}"
            + ("" if prs[n][fname][1] else "*") for n, _, _ in IMAGES))
    patterns["lcl"] = {n: prs[n]["lcl"].get(0, 0) for n, _, _ in IMAGES}
    report["patterns"]["lcl"] = {n: f"0x{patterns['lcl'][n]:x}"
                                 for n, _, _ in IMAGES}
    print()

    def emit(fname, cross, raw):
        print(f"field={fname}")
        print("  raw candidates (within-gen): " +
              " ".join(f"{g}={raw[g]}" for g in GENS))
        found = [c for c in cross if c["tier"] == "FOUND"]
        excluded = [c for c in cross if c["tier"] != "FOUND"]
        for c in found:
            print(f"  FOUND 0x{c['sect']:02x}+0x{c['off']:03x}  [" +
                  " ".join(f"{g}={c['gens'][g]}" for g in GENS) + "]")
            print("    vals: " +
                  " ".join(f"{n}={v}" for n, v in c["values"].items()))
        if excluded:
            print(f"  excluded (confirmed >=2 gens, refuted by one): "
                  f"{len(excluded)}")
            for c in excluded:
                print(f"    0x{c['sect']:02x}+0x{c['off']:03x}  [" +
                      " ".join(f"{g}={c['gens'][g]}" for g in GENS) +
                      f"]  {c['tier']}")
        if not cross:
            print("  cross-version candidates: none")
        print(f"  -> FOUND: {len(found)}, excluded: {len(excluded)}")
        print()

    for fname, _ in FIELD_RE:
        raw, cross = sweep_field(patterns[fname], data, gens)
        report["fields"][fname] = {"raw_candidates": raw, "cross": cross}
        emit(fname, cross, raw)

    raw, cross = sweep_field(patterns["lcl"], data, gens)
    anchor_rows = [c for c in cross
                   if c["sect"] == 0x12 and c["off"] == LCL_ANCHOR
                   and all(c["gens"][g].startswith(("same@", "shifted@0x"))
                           for g in GENS)]
    report["control"] = {"raw_candidates": raw, "cross": cross,
                         "anchor_0x12_0x30b_all_gens": bool(anchor_rows)}
    emit("lcl (control)", cross, raw)
    if anchor_rows:
        print("  CONTROL OK: 0x12+0x30b confirmed in all generations")
    else:
        print("  CONTROL FAILED: lcl anchor not confirmed cross-version — "
              "method broken, results invalid")
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=1))
        print(f"json: {a.json}")
    return 0 if anchor_rows else 1


if __name__ == "__main__":
    sys.exit(main())
