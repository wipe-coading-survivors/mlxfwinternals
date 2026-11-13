#!/usr/bin/env python3
"""Cross-image byte sweep for the IB link-speed enabled-mask byte in
CX-4/CX-4Lx FS3 images (plan 2026-10-07-cx4lx-56-100g, task 2).

Target (H2): a config byte holding the IB-enabled speed mask
(bit map: bit0=SDR, bit1=DDR, bit2=QDR, bit3=FDR10, bit4=FDR,
bit5=EDR):
  56G target  = 0x1f (SDR+DDR+QDR+FDR10+FDR)
  100G target = 0x3f (+EDR)

Method (task-2 brief):
  * group "14.32" (sharp contrast, same layout, different build):
    pattern {1900:0x1f, 4121A-1912:0x07, 4131A-BCA-1912:0x07,
    4131A-GCA-1912:0x07} — 1900 mask measured live (journal
    2026-09-15-cx4lx-ib :313, PDDR Enabled Link Speed after T3-VPI),
    1912 mask = product constant 0x07 (journal 10-06 / T7);
  * group "4706": {456F:0x1f, 456E:0x3f} (FDR-VPI vs EDR-VPI; EN
    cards such as 416A may carry no IB mask — value reported, not
    required);
  * group "12.23": {453A:0x1f} (FDR-VPI, own layout);
  * a raw candidate = (section, rel offset) whose byte equals the
    pattern in ALL images of the group; sections = every ITOC section
    with 0 < size <= 0x20000 B;
  * cross-check of 14.32 raw candidates: "B ok" = 456F==0x1f and
    456E==0x3f at the same rel offset; "A ok" = 453A==0x1f;
    tier FOUND = 14.32 + B + A.
  * candidate checks (step 4): (a) GCA-1912 value == 0x07 (guaranteed
    by the pattern), (b) not the lcl byte 0x12+0x30b, (c) no
    contradictions in the remaining images (full value table printed).

Controls (method must find the known bytes, else exit 1 = broken):
  * lcl: pattern {ACA:0x0b, BCA:0x1b, GCA:0x3b} must yield the anchor
    0x12+0x30b (three 1912 images; 1900 lcl[0]=0x0b is consistent);
  * VPI: pattern {GCA-IB:0x07, BCA-IB:0x07, 1900:0x0a, ACA:0x0a,
    BCA:0x0a, GCA:0x0a} must yield the anchor 0x11+0x2af (VPI
    port0 byte, 0x0a=EN / 0x07=IB, journal 10-06 :298).

STOP condition (plan): if any sweep (groups or controls) yields the
candidate 0x12+0x158 — exit 3 with a STOP banner (T6: 0x158=0x10
breaks the port; the byte must not be changed without a ruling).

Images: 10 vendor .bin from refs/fw/cx-4/ + the 1900 raw dump
(refs/fw/cx-4/dumps/lx_c1_final_rollback-20260919.bin, loaded in
FULL, not an 8 MiB slice: the single ITOC @0x2000 lists all
sections 0x05 @0x4000 … 0xe3 @0xff8140 spanning the ~16 MiB file,
and the NV/dev sections 0xe0-0xe6 sit beyond 8 MiB (0xfa0000-
0xff8140) yet are sweepable (<= 0x20000 B); the raw file is
rejected by `mlxfwutil ab` so this script parses the ITOC itself)
+ the two 14.32 Lx IB images (not in the repo; copy them to
--workdir, e.g. scp root-bazzite:/root/
img_lxqsfp28_1912_{gca,bca}_ib.bin; md5 68bae3dc…/39d36efe…).

Usage: python3 scripts/probes/sweep_ib_mask.py [--json OUT]
       [--workdir /tmp/opencode/56g]
Exit: 0 controls ok, 1 control failed (method broken), 2 missing
input, 3 STOP condition (0x12+0x158 candidate).
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from toc_probe import ITOC_HDR, find_all, bits  # noqa: E402

SECT_MAX = 0x20000
STOP_SECT, STOP_OFF = 0x12, 0x158
LCL_SECT, LCL_OFF = 0x12, 0x30b
VPI_SECT, VPI_OFF = 0x11, 0x2af

VENDOR = [
    ("453A-1223", "refs/fw/cx-4/fw-ConnectX4-rel-12_23_1020-MCX453A-FCA_Ax-UEFI-14.16.17-FlexBoot-3.5.504.bin"),
    ("415A-2302", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_2302-MCX415A-GCA_Ax-UEFI-14.21.17-FlexBoot-3.6.102.bin"),
    ("455A-2302", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-UEFI-14.21.17-FlexBoot-3.6.102.bin"),
    ("413A-4706", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX413A-GCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"),
    ("416A-4706", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX416A-CCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"),
    ("456E-4706", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"),
    ("456F-4706", "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-FCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"),
    ("ACA-1912", "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4121A-ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"),
    ("BCA-1912", "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-BCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"),
    ("GCA-1912", "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"),
]
DUMP = "refs/fw/cx-4/dumps/lx_c1_final_rollback-20260919.bin"
IB_IMGS = ("img_lxqsfp28_1912_gca_ib.bin", "img_lxqsfp28_1912_bca_ib.bin")
IB_NAMES = ("GCA-IB", "BCA-IB")

GROUPS = {
    "14.32": {"1900": 0x1f, "ACA-1912": 0x07, "BCA-1912": 0x07,
              "GCA-1912": 0x07},
    "4706": {"456F-4706": 0x1f, "456E-4706": 0x3f},
    "12.23": {"453A-1223": 0x1f},
}
CONTROLS = {
    "lcl": {"pattern": {"ACA-1912": 0x0b, "BCA-1912": 0x1b,
                        "GCA-1912": 0x3b},
            "anchor": (LCL_SECT, LCL_OFF)},
    "vpi": {"pattern": {"GCA-IB": 0x07, "BCA-IB": 0x07, "1900": 0x0a,
                        "ACA-1912": 0x0a, "BCA-1912": 0x0a,
                        "GCA-1912": 0x0a},
            "anchor": (VPI_SECT, VPI_OFF)},
}


def load_sections(buf: bytes) -> dict:
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


def load_image(path: Path, limit: int | None) -> dict:
    buf = path.read_bytes() if limit is None else path.read_bytes()[:limit]
    return load_sections(buf)


def sweep(data, pattern):
    """(sect, off) raw candidates: byte == pattern in every pattern
    image; sections <= SECT_MAX present in all of them."""
    names = list(pattern)
    out = set()
    sects = set()
    for n in names:
        sects |= {t for t, b in data[n].items()
                  if 0 < len(b) <= SECT_MAX}
    for t in sects:
        have = [n for n in names
                if t in data[n] and 0 < len(data[n][t]) <= SECT_MAX]
        if len(have) < len(names):
            continue
        n = min(len(data[x][t]) for x in have)
        for off in range(n):
            if all(data[x][t][off] == pattern[x] for x in have):
                out.add((t, off))
    return out


def values_row(data, t, off):
    out = {}
    for n in data:
        b = data[n].get(t)
        out[n] = f"0x{b[off]:02x}" if b is not None and off < len(b) else "-"
    return out


def check_stop(found) -> bool:
    for label, cands in found:
        if (STOP_SECT, STOP_OFF) in cands:
            print(f"STOP: candidate == 0x12+0x158 in {label} — T6: "
                  f"0x158=0x10 breaks the port; byte must not be "
                  f"changed without a ruling (plan STOP condition)")
            return True
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", metavar="OUT", help="write JSON report")
    ap.add_argument("--workdir", default="/tmp/opencode/56g",
                    help="dir with the 14.32 Lx IB images (default: %(default)s)")
    a = ap.parse_args(argv)

    workdir = Path(a.workdir)
    data = {}
    for name, rel in VENDOR:
        p = ROOT / rel
        if not p.exists():
            print(f"ERROR: {p} not found", file=sys.stderr)
            return 2
        data[name] = load_image(p, None)
    p = ROOT / DUMP
    if not p.exists():
        print(f"ERROR: {p} not found", file=sys.stderr)
        return 2
    data["1900"] = load_image(p, None)
    for name, fname in zip(IB_NAMES, IB_IMGS):
        p = workdir / fname
        if not p.exists():
            print(f"ERROR: {p} not found (copy the 14.32 Lx IB images "
                  f"to the workdir, e.g. scp root-bazzite:/root/{fname})",
                  file=sys.stderr)
            return 2
        data[name] = load_image(p, None)

    report = {"images": {**{n: r for n, r in VENDOR},
                          "1900": DUMP + " (full, all ITOC sections)",
                         **{n: f"{a.workdir}/{f}"
                            for n, f in zip(IB_NAMES, IB_IMGS)}},
              "controls": {}, "groups": {}}
    print(f"== sweep_ib_mask: {len(data)} images "
          f"(sections <= 0x{SECT_MAX:x})")

    found = []
    ok = True
    for label, ctrl in CONTROLS.items():
        cands = sweep(data, ctrl["pattern"])
        anchor = ctrl["anchor"]
        hit = anchor in cands
        ok &= hit
        found.append((f"control {label}", cands))
        report["controls"][label] = {
            "pattern": {n: f"0x{v:02x}" for n, v in ctrl["pattern"].items()},
            "anchor": f"0x{anchor[0]:02x}+0x{anchor[1]:03x}",
            "raw_candidates": len(cands),
            "anchor_found": hit,
            "candidates": [f"0x{t:02x}+0x{o:03x}" for t, o in sorted(cands)]}
        print(f"control {label}: pattern " +
              " ".join(f"{n}=0x{v:02x}" for n, v in ctrl["pattern"].items()))
        print(f"  raw candidates: {len(cands)}; "
              f"anchor 0x{anchor[0]:02x}+0x{anchor[1]:03x}: "
              f"{'FOUND' if hit else 'NOT FOUND'}")
        if not hit:
            print(f"  CONTROL FAILED — method broken, results invalid")

    groups = {}
    for gname, pattern in GROUPS.items():
        cands = sweep(data, pattern)
        groups[gname] = cands
        found.append((f"group {gname}", cands))
        report["groups"][gname] = {
            "pattern": {n: f"0x{v:02x}" for n, v in pattern.items()},
            "raw_candidates": len(cands)}
    if check_stop(found):
        return 3
    if not ok:
        return 1

    print(f"\ngroup 14.32 (sharp contrast 1900=0x1f vs 1912=0x07):")
    c14 = groups["14.32"]
    print(f"  raw candidates: {len(c14)}")
    rows14 = []
    for t, off in sorted(c14, key=lambda k: (k[0], k[1])):
        if (t, off) == (LCL_SECT, LCL_OFF):
            print(f"  0x{t:02x}+0x{off:03x}  — lcl byte, excluded "
                  f"(step 4b)")
            continue
        vals = values_row(data, t, off)
        b_ok = (vals["456F-4706"] == "0x1f" and vals["456E-4706"] == "0x3f")
        a_ok = vals["453A-1223"] == "0x1f"
        tier = ("FOUND" if b_ok and a_ok else
                "C+B" if b_ok else "C+A" if a_ok else "C-only")
        gca = vals["GCA-1912"]
        row = {"pos": f"0x{t:02x}+0x{off:03x}", "tier": tier,
               "gca_1912": gca, "values": vals}
        rows14.append(row)
        print(f"  {tier:7s} 0x{t:02x}+0x{off:03x}  [B={'ok' if b_ok else 'no'} "
              f"A={'ok' if a_ok else 'no'} GCA={gca}]")
        print("    " + " ".join(f"{n}={v}" for n, v in vals.items()))
    report["groups"]["14.32"]["candidates"] = rows14
    nfound = sum(1 for r in rows14 if r["tier"] == "FOUND")
    print(f"  -> FOUND (14.32+B+A): {nfound}, "
          f"total candidates: {len(rows14)}")

    print("\ngroup 4706 (456F=0x1f vs 456E=0x3f; EN cards reported):")
    c47 = groups["4706"]
    print(f"  raw candidates: {len(c47)}")
    rows47 = []
    for t, off in sorted(c47, key=lambda k: (k[0], k[1])):
        vals = values_row(data, t, off)
        in14 = (t, off) in c14
        row = {"pos": f"0x{t:02x}+0x{off:03x}", "in_14_32": in14,
               "values": vals}
        rows47.append(row)
        print(f"  0x{t:02x}+0x{off:03x}  [14.32={'yes' if in14 else 'no'} "
              f"416A={vals['416A-4706']} 455A={vals['455A-2302']} "
              f"456E={vals['456E-4706']} 456F={vals['456F-4706']} "
              f"1912GCA={vals['GCA-1912']} 1900={vals['1900']}]")
    report["groups"]["4706"]["candidates"] = rows47

    print("\ngroup 12.23 (453A=0x1f):")
    c12 = groups["12.23"]
    inter = sorted(c12 & c14, key=lambda k: (k[0], k[1]))
    print(f"  raw candidates (0x1f bytes in 453A, sections <= 0x{SECT_MAX:x}): "
          f"{len(c12)}")
    print(f"  coinciding with 14.32 candidates (same sect+off): "
          f"{len(inter)}")
    for t, off in inter:
        print(f"    0x{t:02x}+0x{off:03x}")
    report["groups"]["12.23"]["candidates_14_32_overlap"] = [
        f"0x{t:02x}+0x{off:03x}" for t, off in inter]
    report["groups"]["12.23"]["all_positions"] = [
        f"0x{t:02x}+0x{off:03x}" for t, off in sorted(c12)]

    verdict = ("found" if nfound else
               "found (partial)" if rows14 else "not found")
    print(f"\nverdict: IB-enabled-mask byte {verdict}; "
          f"targets: 56G -> 0x1f, 100G -> 0x3f")
    report["verdict"] = verdict
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=1))
        print(f"json: {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
